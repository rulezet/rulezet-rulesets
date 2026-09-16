rule TTP_XOR_MULT_DOSStub_e4d6 {
  strings:
    $key_e4d6 = { b0 be [2] c4 a6 [2] 83 a4 [2] c4 b5 [2] 8a b9 [2] 86 b3 [2] 91 b8 [2] 8a f6 [2] b7 }

  condition:
    any of them
}