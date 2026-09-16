rule TTP_XOR_MULT_DOSStub_a141 {
  strings:
    $key_a141 = { f5 29 [2] 81 31 [2] c6 33 [2] 81 22 [2] cf 2e [2] c3 24 [2] d4 2f [2] cf 61 [2] f2 }

  condition:
    any of them
}