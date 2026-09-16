rule TTP_XOR_MULT_DOSStub_e4b2 {
  strings:
    $key_e4b2 = { b0 da [2] c4 c2 [2] 83 c0 [2] c4 d1 [2] 8a dd [2] 86 d7 [2] 91 dc [2] 8a 92 [2] b7 }

  condition:
    any of them
}