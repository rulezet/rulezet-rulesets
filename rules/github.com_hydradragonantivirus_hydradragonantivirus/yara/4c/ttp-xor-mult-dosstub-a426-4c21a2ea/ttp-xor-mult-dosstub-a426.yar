rule TTP_XOR_MULT_DOSStub_a426 {
  strings:
    $key_a426 = { f0 4e [2] 84 56 [2] c3 54 [2] 84 45 [2] ca 49 [2] c6 43 [2] d1 48 [2] ca 06 [2] f7 }

  condition:
    any of them
}