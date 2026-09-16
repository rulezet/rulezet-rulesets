rule TTP_XOR_MULT_DOSStub_e8c1 {
  strings:
    $key_e8c1 = { bc a9 [2] c8 b1 [2] 8f b3 [2] c8 a2 [2] 86 ae [2] 8a a4 [2] 9d af [2] 86 e1 [2] bb }

  condition:
    any of them
}