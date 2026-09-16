rule TTP_XOR_MULT_DOSStub_e1d0 {
  strings:
    $key_e1d0 = { b5 b8 [2] c1 a0 [2] 86 a2 [2] c1 b3 [2] 8f bf [2] 83 b5 [2] 94 be [2] 8f f0 [2] b2 }

  condition:
    any of them
}