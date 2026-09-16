rule TTP_XOR_MULT_DOSStub_4266 {
  strings:
    $key_4266 = { 16 0e [2] 62 16 [2] 25 14 [2] 62 05 [2] 2c 09 [2] 20 03 [2] 37 08 [2] 2c 46 [2] 11 }

  condition:
    any of them
}