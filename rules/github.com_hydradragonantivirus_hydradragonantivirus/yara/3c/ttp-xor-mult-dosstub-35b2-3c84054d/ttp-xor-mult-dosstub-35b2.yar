rule TTP_XOR_MULT_DOSStub_35b2 {
  strings:
    $key_35b2 = { 61 da [2] 15 c2 [2] 52 c0 [2] 15 d1 [2] 5b dd [2] 57 d7 [2] 40 dc [2] 5b 92 [2] 66 }

  condition:
    any of them
}