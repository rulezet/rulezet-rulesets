rule TTP_XOR_MULT_DOSStub_a781 {
  strings:
    $key_a781 = { f3 e9 [2] 87 f1 [2] c0 f3 [2] 87 e2 [2] c9 ee [2] c5 e4 [2] d2 ef [2] c9 a1 [2] f4 }

  condition:
    any of them
}