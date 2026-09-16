rule TTP_XOR_MULT_DOSStub_a483 {
  strings:
    $key_a483 = { f0 eb [2] 84 f3 [2] c3 f1 [2] 84 e0 [2] ca ec [2] c6 e6 [2] d1 ed [2] ca a3 [2] f7 }

  condition:
    any of them
}