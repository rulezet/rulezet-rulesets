rule TTP_XOR_MULT_DOSStub_2f1b {
  strings:
    $key_2f1b = { 7b 73 [2] 0f 6b [2] 48 69 [2] 0f 78 [2] 41 74 [2] 4d 7e [2] 5a 75 [2] 41 3b [2] 7c }

  condition:
    any of them
}