rule TTP_XOR_MULT_DOSStub_7847 {
  strings:
    $key_7847 = { 2c 2f [2] 58 37 [2] 1f 35 [2] 58 24 [2] 16 28 [2] 1a 22 [2] 0d 29 [2] 16 67 [2] 2b }

  condition:
    any of them
}