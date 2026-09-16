rule TTP_XOR_MULT_DOSStub_4275 {
  strings:
    $key_4275 = { 16 1d [2] 62 05 [2] 25 07 [2] 62 16 [2] 2c 1a [2] 20 10 [2] 37 1b [2] 2c 55 [2] 11 }

  condition:
    any of them
}