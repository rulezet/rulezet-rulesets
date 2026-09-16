rule TTP_XOR_MULT_DOSStub_3f1b {
  strings:
    $key_3f1b = { 6b 73 [2] 1f 6b [2] 58 69 [2] 1f 78 [2] 51 74 [2] 5d 7e [2] 4a 75 [2] 51 3b [2] 6c }

  condition:
    any of them
}