rule TTP_XOR_MULT_DOSStub_a436 {
  strings:
    $key_a436 = { f0 5e [2] 84 46 [2] c3 44 [2] 84 55 [2] ca 59 [2] c6 53 [2] d1 58 [2] ca 16 [2] f7 }

  condition:
    any of them
}