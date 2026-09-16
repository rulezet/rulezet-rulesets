rule TTP_XOR_MULT_DOSStub_a456 {
  strings:
    $key_a456 = { f0 3e [2] 84 26 [2] c3 24 [2] 84 35 [2] ca 39 [2] c6 33 [2] d1 38 [2] ca 76 [2] f7 }

  condition:
    any of them
}