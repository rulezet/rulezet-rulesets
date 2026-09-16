rule TTP_XOR_MULT_DOSStub_a148 {
  strings:
    $key_a148 = { f5 20 [2] 81 38 [2] c6 3a [2] 81 2b [2] cf 27 [2] c3 2d [2] d4 26 [2] cf 68 [2] f2 }

  condition:
    any of them
}