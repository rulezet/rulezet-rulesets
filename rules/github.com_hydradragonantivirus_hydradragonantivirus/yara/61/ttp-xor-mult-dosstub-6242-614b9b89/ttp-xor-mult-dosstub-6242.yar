rule TTP_XOR_MULT_DOSStub_6242 {
  strings:
    $key_6242 = { 36 2a [2] 42 32 [2] 05 30 [2] 42 21 [2] 0c 2d [2] 00 27 [2] 17 2c [2] 0c 62 [2] 31 }

  condition:
    any of them
}