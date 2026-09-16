rule TTP_XOR_MULT_DOSStub_3a72 {
  strings:
    $key_3a72 = { 6e 1a [2] 1a 02 [2] 5d 00 [2] 1a 11 [2] 54 1d [2] 58 17 [2] 4f 1c [2] 54 52 [2] 69 }

  condition:
    any of them
}