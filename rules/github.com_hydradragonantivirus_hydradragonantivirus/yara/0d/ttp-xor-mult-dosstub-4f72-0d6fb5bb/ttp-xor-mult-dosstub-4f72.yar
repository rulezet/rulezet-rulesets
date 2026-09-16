rule TTP_XOR_MULT_DOSStub_4f72 {
  strings:
    $key_4f72 = { 1b 1a [2] 6f 02 [2] 28 00 [2] 6f 11 [2] 21 1d [2] 2d 17 [2] 3a 1c [2] 21 52 [2] 1c }

  condition:
    any of them
}