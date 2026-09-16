rule TTP_XOR_MULT_DOSStub_38c7 {
  strings:
    $key_38c7 = { 6c af [2] 18 b7 [2] 5f b5 [2] 18 a4 [2] 56 a8 [2] 5a a2 [2] 4d a9 [2] 56 e7 [2] 6b }

  condition:
    any of them
}