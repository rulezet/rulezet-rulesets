rule TTP_XOR_MULT_DOSStub_7856 {
  strings:
    $key_7856 = { 2c 3e [2] 58 26 [2] 1f 24 [2] 58 35 [2] 16 39 [2] 1a 33 [2] 0d 38 [2] 16 76 [2] 2b }

  condition:
    any of them
}