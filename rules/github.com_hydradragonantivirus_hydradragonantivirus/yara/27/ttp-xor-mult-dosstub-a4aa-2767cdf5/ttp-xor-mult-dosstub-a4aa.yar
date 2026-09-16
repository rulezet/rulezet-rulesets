rule TTP_XOR_MULT_DOSStub_a4aa {
  strings:
    $key_a4aa = { f0 c2 [2] 84 da [2] c3 d8 [2] 84 c9 [2] ca c5 [2] c6 cf [2] d1 c4 [2] ca 8a [2] f7 }

  condition:
    any of them
}