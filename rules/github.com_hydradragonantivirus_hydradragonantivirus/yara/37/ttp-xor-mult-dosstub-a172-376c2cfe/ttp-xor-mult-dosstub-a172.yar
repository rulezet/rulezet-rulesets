rule TTP_XOR_MULT_DOSStub_a172 {
  strings:
    $key_a172 = { f5 1a [2] 81 02 [2] c6 00 [2] 81 11 [2] cf 1d [2] c3 17 [2] d4 1c [2] cf 52 [2] f2 }

  condition:
    any of them
}