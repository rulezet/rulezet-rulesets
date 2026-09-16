rule TTP_XOR_MULT_DOSStub_4271 {
  strings:
    $key_4271 = { 16 19 [2] 62 01 [2] 25 03 [2] 62 12 [2] 2c 1e [2] 20 14 [2] 37 1f [2] 2c 51 [2] 11 }

  condition:
    any of them
}