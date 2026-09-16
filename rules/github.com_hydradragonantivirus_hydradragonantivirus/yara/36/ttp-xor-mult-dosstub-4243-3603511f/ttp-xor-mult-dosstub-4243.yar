rule TTP_XOR_MULT_DOSStub_4243 {
  strings:
    $key_4243 = { 16 2b [2] 62 33 [2] 25 31 [2] 62 20 [2] 2c 2c [2] 20 26 [2] 37 2d [2] 2c 63 [2] 11 }

  condition:
    any of them
}