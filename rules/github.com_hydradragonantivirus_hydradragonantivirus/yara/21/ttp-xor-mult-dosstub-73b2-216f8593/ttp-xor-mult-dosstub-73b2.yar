rule TTP_XOR_MULT_DOSStub_73b2 {
  strings:
    $key_73b2 = { 27 da [2] 53 c2 [2] 14 c0 [2] 53 d1 [2] 1d dd [2] 11 d7 [2] 06 dc [2] 1d 92 [2] 20 }

  condition:
    any of them
}