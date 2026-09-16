rule TTP_XOR_MULT_DOSStub_e180 {
  strings:
    $key_e180 = { b5 e8 [2] c1 f0 [2] 86 f2 [2] c1 e3 [2] 8f ef [2] 83 e5 [2] 94 ee [2] 8f a0 [2] b2 }

  condition:
    any of them
}