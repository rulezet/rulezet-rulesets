rule TTP_XOR_MULT_DOSStub_a487 {
  strings:
    $key_a487 = { f0 ef [2] 84 f7 [2] c3 f5 [2] 84 e4 [2] ca e8 [2] c6 e2 [2] d1 e9 [2] ca a7 [2] f7 }

  condition:
    any of them
}