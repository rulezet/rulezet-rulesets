rule TTP_XOR_MULT_DOSStub_e1b4 {
  strings:
    $key_e1b4 = { b5 dc [2] c1 c4 [2] 86 c6 [2] c1 d7 [2] 8f db [2] 83 d1 [2] 94 da [2] 8f 94 [2] b2 }

  condition:
    any of them
}