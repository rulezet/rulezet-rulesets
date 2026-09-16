rule TTP_XOR_MULT_DOSStub_e0c6 {
  strings:
    $key_e0c6 = { b4 ae [2] c0 b6 [2] 87 b4 [2] c0 a5 [2] 8e a9 [2] 82 a3 [2] 95 a8 [2] 8e e6 [2] b3 }

  condition:
    any of them
}