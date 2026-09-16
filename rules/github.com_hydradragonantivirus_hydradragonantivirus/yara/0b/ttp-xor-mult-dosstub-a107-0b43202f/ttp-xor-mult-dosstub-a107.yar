rule TTP_XOR_MULT_DOSStub_a107 {
  strings:
    $key_a107 = { f5 6f [2] 81 77 [2] c6 75 [2] 81 64 [2] cf 68 [2] c3 62 [2] d4 69 [2] cf 27 [2] f2 }

  condition:
    any of them
}