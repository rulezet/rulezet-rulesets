rule TTP_XOR_MULT_DOSStub_a174 {
  strings:
    $key_a174 = { f5 1c [2] 81 04 [2] c6 06 [2] 81 17 [2] cf 1b [2] c3 11 [2] d4 1a [2] cf 54 [2] f2 }

  condition:
    any of them
}