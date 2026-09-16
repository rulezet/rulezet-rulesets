rule TTP_XOR_MULT_DOSStub_73b4 {
  strings:
    $key_73b4 = { 27 dc [2] 53 c4 [2] 14 c6 [2] 53 d7 [2] 1d db [2] 11 d1 [2] 06 da [2] 1d 94 [2] 20 }

  condition:
    any of them
}