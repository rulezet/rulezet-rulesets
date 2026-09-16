rule TTP_XOR_MULT_DOSStub_e5c6 {
  strings:
    $key_e5c6 = { b1 ae [2] c5 b6 [2] 82 b4 [2] c5 a5 [2] 8b a9 [2] 87 a3 [2] 90 a8 [2] 8b e6 [2] b6 }

  condition:
    any of them
}