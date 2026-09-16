rule TTP_XOR_MULT_DOSStub_45b2 {
  strings:
    $key_45b2 = { 11 da [2] 65 c2 [2] 22 c0 [2] 65 d1 [2] 2b dd [2] 27 d7 [2] 30 dc [2] 2b 92 [2] 16 }

  condition:
    any of them
}