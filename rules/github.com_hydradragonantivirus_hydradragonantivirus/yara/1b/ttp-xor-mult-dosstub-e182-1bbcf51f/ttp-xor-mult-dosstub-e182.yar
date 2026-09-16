rule TTP_XOR_MULT_DOSStub_e182 {
  strings:
    $key_e182 = { b5 ea [2] c1 f2 [2] 86 f0 [2] c1 e1 [2] 8f ed [2] 83 e7 [2] 94 ec [2] 8f a2 [2] b2 }

  condition:
    any of them
}