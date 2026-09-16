rule TTP_XOR_MULT_DOSStub_4f54 {
  strings:
    $key_4f54 = { 1b 3c [2] 6f 24 [2] 28 26 [2] 6f 37 [2] 21 3b [2] 2d 31 [2] 3a 3a [2] 21 74 [2] 1c }

  condition:
    any of them
}