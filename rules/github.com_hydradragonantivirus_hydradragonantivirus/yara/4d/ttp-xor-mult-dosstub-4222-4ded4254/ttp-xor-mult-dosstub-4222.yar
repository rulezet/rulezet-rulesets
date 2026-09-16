rule TTP_XOR_MULT_DOSStub_4222 {
  strings:
    $key_4222 = { 16 4a [2] 62 52 [2] 25 50 [2] 62 41 [2] 2c 4d [2] 20 47 [2] 37 4c [2] 2c 02 [2] 11 }

  condition:
    any of them
}