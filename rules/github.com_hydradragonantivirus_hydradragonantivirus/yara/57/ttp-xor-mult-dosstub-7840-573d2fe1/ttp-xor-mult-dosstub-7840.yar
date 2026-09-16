rule TTP_XOR_MULT_DOSStub_7840 {
  strings:
    $key_7840 = { 2c 28 [2] 58 30 [2] 1f 32 [2] 58 23 [2] 16 2f [2] 1a 25 [2] 0d 2e [2] 16 60 [2] 2b }

  condition:
    any of them
}