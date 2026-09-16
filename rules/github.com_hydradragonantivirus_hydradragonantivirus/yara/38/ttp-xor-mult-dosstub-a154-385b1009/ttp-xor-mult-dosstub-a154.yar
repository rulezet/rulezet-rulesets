rule TTP_XOR_MULT_DOSStub_a154 {
  strings:
    $key_a154 = { f5 3c [2] 81 24 [2] c6 26 [2] 81 37 [2] cf 3b [2] c3 31 [2] d4 3a [2] cf 74 [2] f2 }

  condition:
    any of them
}