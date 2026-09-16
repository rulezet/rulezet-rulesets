rule TTP_XOR_MULT_DOSStub_68c1 {
  strings:
    $key_68c1 = { 3c a9 [2] 48 b1 [2] 0f b3 [2] 48 a2 [2] 06 ae [2] 0a a4 [2] 1d af [2] 06 e1 [2] 3b }

  condition:
    any of them
}