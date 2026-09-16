rule TTP_XOR_MULT_DOSStub_e490 {
  strings:
    $key_e490 = { b0 f8 [2] c4 e0 [2] 83 e2 [2] c4 f3 [2] 8a ff [2] 86 f5 [2] 91 fe [2] 8a b0 [2] b7 }

  condition:
    any of them
}