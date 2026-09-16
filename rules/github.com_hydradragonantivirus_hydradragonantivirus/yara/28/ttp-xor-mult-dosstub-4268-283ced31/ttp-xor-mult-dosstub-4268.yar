rule TTP_XOR_MULT_DOSStub_4268 {
  strings:
    $key_4268 = { 16 00 [2] 62 18 [2] 25 1a [2] 62 0b [2] 2c 07 [2] 20 0d [2] 37 06 [2] 2c 48 [2] 11 }

  condition:
    any of them
}