rule TTP_XOR_MULT_DOSStub_a787 {
  strings:
    $key_a787 = { f3 ef [2] 87 f7 [2] c0 f5 [2] 87 e4 [2] c9 e8 [2] c5 e2 [2] d2 e9 [2] c9 a7 [2] f4 }

  condition:
    any of them
}