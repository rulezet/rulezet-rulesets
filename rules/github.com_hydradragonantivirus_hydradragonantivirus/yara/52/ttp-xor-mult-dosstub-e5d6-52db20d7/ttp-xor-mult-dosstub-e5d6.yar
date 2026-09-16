rule TTP_XOR_MULT_DOSStub_e5d6 {
  strings:
    $key_e5d6 = { b1 be [2] c5 a6 [2] 82 a4 [2] c5 b5 [2] 8b b9 [2] 87 b3 [2] 90 b8 [2] 8b f6 [2] b6 }

  condition:
    any of them
}