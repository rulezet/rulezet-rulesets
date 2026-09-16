rule TTP_XOR_MULT_DOSStub_4276 {
  strings:
    $key_4276 = { 16 1e [2] 62 06 [2] 25 04 [2] 62 15 [2] 2c 19 [2] 20 13 [2] 37 18 [2] 2c 56 [2] 11 }

  condition:
    any of them
}