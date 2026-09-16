rule TTP_XOR_MULT_DOSStub_64b2 {
  strings:
    $key_64b2 = { 30 da [2] 44 c2 [2] 03 c0 [2] 44 d1 [2] 0a dd [2] 06 d7 [2] 11 dc [2] 0a 92 [2] 37 }

  condition:
    any of them
}