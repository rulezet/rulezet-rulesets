rule TTP_XOR_MULT_DOSStub_a406 {
  strings:
    $key_a406 = { f0 6e [2] 84 76 [2] c3 74 [2] 84 65 [2] ca 69 [2] c6 63 [2] d1 68 [2] ca 26 [2] f7 }

  condition:
    any of them
}