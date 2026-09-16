rule TTP_XOR_MULT_DOSStub_a106 {
  strings:
    $key_a106 = { f5 6e [2] 81 76 [2] c6 74 [2] 81 65 [2] cf 69 [2] c3 63 [2] d4 68 [2] cf 26 [2] f2 }

  condition:
    any of them
}