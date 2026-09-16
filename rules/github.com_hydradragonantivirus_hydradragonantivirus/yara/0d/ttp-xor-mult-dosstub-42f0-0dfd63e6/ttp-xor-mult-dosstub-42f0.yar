rule TTP_XOR_MULT_DOSStub_42f0 {
  strings:
    $key_42f0 = { 16 98 [2] 62 80 [2] 25 82 [2] 62 93 [2] 2c 9f [2] 20 95 [2] 37 9e [2] 2c d0 [2] 11 }

  condition:
    any of them
}