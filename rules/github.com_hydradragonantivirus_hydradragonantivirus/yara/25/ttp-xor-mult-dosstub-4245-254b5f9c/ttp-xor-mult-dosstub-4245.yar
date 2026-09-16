rule TTP_XOR_MULT_DOSStub_4245 {
  strings:
    $key_4245 = { 16 2d [2] 62 35 [2] 25 37 [2] 62 26 [2] 2c 2a [2] 20 20 [2] 37 2b [2] 2c 65 [2] 11 }

  condition:
    any of them
}