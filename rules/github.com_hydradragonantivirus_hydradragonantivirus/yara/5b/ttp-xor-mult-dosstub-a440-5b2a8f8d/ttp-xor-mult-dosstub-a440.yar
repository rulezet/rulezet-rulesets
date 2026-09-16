rule TTP_XOR_MULT_DOSStub_a440 {
  strings:
    $key_a440 = { f0 28 [2] 84 30 [2] c3 32 [2] 84 23 [2] ca 2f [2] c6 25 [2] d1 2e [2] ca 60 [2] f7 }

  condition:
    any of them
}