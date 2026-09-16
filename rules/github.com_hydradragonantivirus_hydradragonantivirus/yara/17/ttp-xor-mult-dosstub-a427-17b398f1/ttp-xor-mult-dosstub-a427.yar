rule TTP_XOR_MULT_DOSStub_a427 {
  strings:
    $key_a427 = { f0 4f [2] 84 57 [2] c3 55 [2] 84 44 [2] ca 48 [2] c6 42 [2] d1 49 [2] ca 07 [2] f7 }

  condition:
    any of them
}