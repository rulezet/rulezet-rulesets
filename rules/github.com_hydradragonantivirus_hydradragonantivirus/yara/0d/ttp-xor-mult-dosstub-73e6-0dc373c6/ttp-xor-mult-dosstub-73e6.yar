rule TTP_XOR_MULT_DOSStub_73e6 {
  strings:
    $key_73e6 = { 27 8e [2] 53 96 [2] 14 94 [2] 53 85 [2] 1d 89 [2] 11 83 [2] 06 88 [2] 1d c6 [2] 20 }

  condition:
    any of them
}