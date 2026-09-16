rule TTP_XOR_MULT_DOSStub_a680 {
  strings:
    $key_a680 = { f2 e8 [2] 86 f0 [2] c1 f2 [2] 86 e3 [2] c8 ef [2] c4 e5 [2] d3 ee [2] c8 a0 [2] f5 }

  condition:
    any of them
}