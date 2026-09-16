rule TTP_XOR_MULT_DOSStub_a131 {
  strings:
    $key_a131 = { f5 59 [2] 81 41 [2] c6 43 [2] 81 52 [2] cf 5e [2] c3 54 [2] d4 5f [2] cf 11 [2] f2 }

  condition:
    any of them
}