rule TTP_XOR_MULT_DOSStub_e7b4 {
  strings:
    $key_e7b4 = { b3 dc [2] c7 c4 [2] 80 c6 [2] c7 d7 [2] 89 db [2] 85 d1 [2] 92 da [2] 89 94 [2] b4 }

  condition:
    any of them
}