rule TTP_XOR_MULT_DOSStub_e1c1 {
  strings:
    $key_e1c1 = { b5 a9 [2] c1 b1 [2] 86 b3 [2] c1 a2 [2] 8f ae [2] 83 a4 [2] 94 af [2] 8f e1 [2] b2 }

  condition:
    any of them
}