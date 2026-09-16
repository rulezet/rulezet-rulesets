rule TTP_XOR_MULT_DOSStub_4f1b {
  strings:
    $key_4f1b = { 1b 73 [2] 6f 6b [2] 28 69 [2] 6f 78 [2] 21 74 [2] 2d 7e [2] 3a 75 [2] 21 3b [2] 1c }

  condition:
    any of them
}