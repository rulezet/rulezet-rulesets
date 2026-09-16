rule TTP_XOR_MULT_DOSStub_a190 {
  strings:
    $key_a190 = { f5 f8 [2] 81 e0 [2] c6 e2 [2] 81 f3 [2] cf ff [2] c3 f5 [2] d4 fe [2] cf b0 [2] f2 }

  condition:
    any of them
}