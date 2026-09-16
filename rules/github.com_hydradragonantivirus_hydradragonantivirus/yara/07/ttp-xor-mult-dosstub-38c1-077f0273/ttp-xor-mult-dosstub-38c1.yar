rule TTP_XOR_MULT_DOSStub_38c1 {
  strings:
    $key_38c1 = { 6c a9 [2] 18 b1 [2] 5f b3 [2] 18 a2 [2] 56 ae [2] 5a a4 [2] 4d af [2] 56 e1 [2] 6b }

  condition:
    any of them
}