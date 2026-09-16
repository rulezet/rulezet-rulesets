rule TTP_XOR_MULT_DOSStub_a147 {
  strings:
    $key_a147 = { f5 2f [2] 81 37 [2] c6 35 [2] 81 24 [2] cf 28 [2] c3 22 [2] d4 29 [2] cf 67 [2] f2 }

  condition:
    any of them
}