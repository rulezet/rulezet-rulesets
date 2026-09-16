rule TTP_XOR_MULT_DOSStub_4eba {
  strings:
    $key_4eba = { 1a d2 [2] 6e ca [2] 29 c8 [2] 6e d9 [2] 20 d5 [2] 2c df [2] 3b d4 [2] 20 9a [2] 1d }

  condition:
    any of them
}