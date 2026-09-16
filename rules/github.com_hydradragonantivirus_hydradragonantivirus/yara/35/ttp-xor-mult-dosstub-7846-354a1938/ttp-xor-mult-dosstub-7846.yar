rule TTP_XOR_MULT_DOSStub_7846 {
  strings:
    $key_7846 = { 2c 2e [2] 58 36 [2] 1f 34 [2] 58 25 [2] 16 29 [2] 1a 23 [2] 0d 28 [2] 16 66 [2] 2b }

  condition:
    any of them
}