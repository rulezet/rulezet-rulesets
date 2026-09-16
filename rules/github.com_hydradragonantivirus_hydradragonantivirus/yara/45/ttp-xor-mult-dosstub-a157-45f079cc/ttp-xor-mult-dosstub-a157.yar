rule TTP_XOR_MULT_DOSStub_a157 {
  strings:
    $key_a157 = { f5 3f [2] 81 27 [2] c6 25 [2] 81 34 [2] cf 38 [2] c3 32 [2] d4 39 [2] cf 77 [2] f2 }

  condition:
    any of them
}