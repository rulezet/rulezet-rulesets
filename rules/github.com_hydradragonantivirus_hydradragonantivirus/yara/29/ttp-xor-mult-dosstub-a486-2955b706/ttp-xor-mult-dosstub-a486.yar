rule TTP_XOR_MULT_DOSStub_a486 {
  strings:
    $key_a486 = { f0 ee [2] 84 f6 [2] c3 f4 [2] 84 e5 [2] ca e9 [2] c6 e3 [2] d1 e8 [2] ca a6 [2] f7 }

  condition:
    any of them
}