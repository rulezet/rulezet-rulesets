rule TTP_XOR_MULT_DOSStub_e196 {
  strings:
    $key_e196 = { b5 fe [2] c1 e6 [2] 86 e4 [2] c1 f5 [2] 8f f9 [2] 83 f3 [2] 94 f8 [2] 8f b6 [2] b2 }

  condition:
    any of them
}