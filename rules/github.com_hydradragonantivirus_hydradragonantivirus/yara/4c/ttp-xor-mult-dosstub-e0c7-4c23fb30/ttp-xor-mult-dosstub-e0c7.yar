rule TTP_XOR_MULT_DOSStub_e0c7 {
  strings:
    $key_e0c7 = { b4 af [2] c0 b7 [2] 87 b5 [2] c0 a4 [2] 8e a8 [2] 82 a2 [2] 95 a9 [2] 8e e7 [2] b3 }

  condition:
    any of them
}