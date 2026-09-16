rule TTP_XOR_MULT_DOSStub_a126 {
  strings:
    $key_a126 = { f5 4e [2] 81 56 [2] c6 54 [2] 81 45 [2] cf 49 [2] c3 43 [2] d4 48 [2] cf 06 [2] f2 }

  condition:
    any of them
}