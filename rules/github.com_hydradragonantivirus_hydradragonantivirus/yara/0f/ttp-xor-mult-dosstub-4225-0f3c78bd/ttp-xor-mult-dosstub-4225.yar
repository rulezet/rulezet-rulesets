rule TTP_XOR_MULT_DOSStub_4225 {
  strings:
    $key_4225 = { 16 4d [2] 62 55 [2] 25 57 [2] 62 46 [2] 2c 4a [2] 20 40 [2] 37 4b [2] 2c 05 [2] 11 }

  condition:
    any of them
}