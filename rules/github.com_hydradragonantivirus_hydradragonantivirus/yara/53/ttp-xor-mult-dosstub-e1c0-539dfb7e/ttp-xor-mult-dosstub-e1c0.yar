rule TTP_XOR_MULT_DOSStub_e1c0 {
  strings:
    $key_e1c0 = { b5 a8 [2] c1 b0 [2] 86 b2 [2] c1 a3 [2] 8f af [2] 83 a5 [2] 94 ae [2] 8f e0 [2] b2 }

  condition:
    any of them
}