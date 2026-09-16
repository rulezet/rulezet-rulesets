rule TTP_XOR_MULT_DOSStub_4260 {
  strings:
    $key_4260 = { 16 08 [2] 62 10 [2] 25 12 [2] 62 03 [2] 2c 0f [2] 20 05 [2] 37 0e [2] 2c 40 [2] 11 }

  condition:
    any of them
}