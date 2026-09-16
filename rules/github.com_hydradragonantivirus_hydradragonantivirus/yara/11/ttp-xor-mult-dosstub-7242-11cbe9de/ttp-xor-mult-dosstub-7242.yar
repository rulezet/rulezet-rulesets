rule TTP_XOR_MULT_DOSStub_7242 {
  strings:
    $key_7242 = { 26 2a [2] 52 32 [2] 15 30 [2] 52 21 [2] 1c 2d [2] 10 27 [2] 07 2c [2] 1c 62 [2] 21 }

  condition:
    any of them
}