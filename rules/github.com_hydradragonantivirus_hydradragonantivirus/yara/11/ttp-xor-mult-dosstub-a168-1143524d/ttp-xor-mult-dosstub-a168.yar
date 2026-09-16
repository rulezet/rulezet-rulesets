rule TTP_XOR_MULT_DOSStub_a168 {
  strings:
    $key_a168 = { f5 00 [2] 81 18 [2] c6 1a [2] 81 0b [2] cf 07 [2] c3 0d [2] d4 06 [2] cf 48 [2] f2 }

  condition:
    any of them
}