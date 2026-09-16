rule TTP_XOR_MULT_DOSStub_4277 {
  strings:
    $key_4277 = { 16 1f [2] 62 07 [2] 25 05 [2] 62 14 [2] 2c 18 [2] 20 12 [2] 37 19 [2] 2c 57 [2] 11 }

  condition:
    any of them
}