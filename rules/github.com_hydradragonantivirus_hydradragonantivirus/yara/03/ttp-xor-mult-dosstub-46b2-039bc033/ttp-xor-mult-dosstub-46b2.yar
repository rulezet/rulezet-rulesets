rule TTP_XOR_MULT_DOSStub_46b2 {
  strings:
    $key_46b2 = { 12 da [2] 66 c2 [2] 21 c0 [2] 66 d1 [2] 28 dd [2] 24 d7 [2] 33 dc [2] 28 92 [2] 15 }

  condition:
    any of them
}