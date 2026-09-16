rule TTP_XOR_MULT_DOSStub_e1c8 {
  strings:
    $key_e1c8 = { b5 a0 [2] c1 b8 [2] 86 ba [2] c1 ab [2] 8f a7 [2] 83 ad [2] 94 a6 [2] 8f e8 [2] b2 }

  condition:
    any of them
}