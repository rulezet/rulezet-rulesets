rule TTP_XOR_MULT_DOSStub_0f1b {
  strings:
    $key_0f1b = { 5b 73 [2] 2f 6b [2] 68 69 [2] 2f 78 [2] 61 74 [2] 6d 7e [2] 7a 75 [2] 61 3b [2] 5c }

  condition:
    any of them
}