rule TTP_XOR_MULT_DOSStub_7eba {
  strings:
    $key_7eba = { 2a d2 [2] 5e ca [2] 19 c8 [2] 5e d9 [2] 10 d5 [2] 1c df [2] 0b d4 [2] 10 9a [2] 2d }

  condition:
    any of them
}