rule TTP_XOR_MULT_DOSStub_77b2 {
  strings:
    $key_77b2 = { 23 da [2] 57 c2 [2] 10 c0 [2] 57 d1 [2] 19 dd [2] 15 d7 [2] 02 dc [2] 19 92 [2] 24 }

  condition:
    any of them
}