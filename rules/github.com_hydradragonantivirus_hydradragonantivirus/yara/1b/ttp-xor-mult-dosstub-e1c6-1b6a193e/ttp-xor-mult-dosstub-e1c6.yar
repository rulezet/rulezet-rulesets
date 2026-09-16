rule TTP_XOR_MULT_DOSStub_e1c6 {
  strings:
    $key_e1c6 = { b5 ae [2] c1 b6 [2] 86 b4 [2] c1 a5 [2] 8f a9 [2] 83 a3 [2] 94 a8 [2] 8f e6 [2] b2 }

  condition:
    any of them
}