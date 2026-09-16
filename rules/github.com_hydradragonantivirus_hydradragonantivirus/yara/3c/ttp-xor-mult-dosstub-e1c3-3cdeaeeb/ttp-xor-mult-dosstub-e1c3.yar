rule TTP_XOR_MULT_DOSStub_e1c3 {
  strings:
    $key_e1c3 = { b5 ab [2] c1 b3 [2] 86 b1 [2] c1 a0 [2] 8f ac [2] 83 a6 [2] 94 ad [2] 8f e3 [2] b2 }

  condition:
    any of them
}