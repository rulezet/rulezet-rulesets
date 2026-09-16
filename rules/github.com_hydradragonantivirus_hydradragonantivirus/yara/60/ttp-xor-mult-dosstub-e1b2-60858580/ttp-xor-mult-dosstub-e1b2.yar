rule TTP_XOR_MULT_DOSStub_e1b2 {
  strings:
    $key_e1b2 = { b5 da [2] c1 c2 [2] 86 c0 [2] c1 d1 [2] 8f dd [2] 83 d7 [2] 94 dc [2] 8f 92 [2] b2 }

  condition:
    any of them
}