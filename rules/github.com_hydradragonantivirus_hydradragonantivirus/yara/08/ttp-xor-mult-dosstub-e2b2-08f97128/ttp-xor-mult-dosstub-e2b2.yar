rule TTP_XOR_MULT_DOSStub_e2b2 {
  strings:
    $key_e2b2 = { b6 da [2] c2 c2 [2] 85 c0 [2] c2 d1 [2] 8c dd [2] 80 d7 [2] 97 dc [2] 8c 92 [2] b1 }

  condition:
    any of them
}