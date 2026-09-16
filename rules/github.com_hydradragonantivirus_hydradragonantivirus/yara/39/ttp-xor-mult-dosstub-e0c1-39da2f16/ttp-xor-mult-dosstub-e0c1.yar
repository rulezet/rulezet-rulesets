rule TTP_XOR_MULT_DOSStub_e0c1 {
  strings:
    $key_e0c1 = { b4 a9 [2] c0 b1 [2] 87 b3 [2] c0 a2 [2] 8e ae [2] 82 a4 [2] 95 af [2] 8e e1 [2] b3 }

  condition:
    any of them
}