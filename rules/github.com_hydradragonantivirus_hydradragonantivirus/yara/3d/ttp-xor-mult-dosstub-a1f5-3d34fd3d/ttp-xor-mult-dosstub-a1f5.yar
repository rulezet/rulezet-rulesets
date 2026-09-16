rule TTP_XOR_MULT_DOSStub_a1f5 {
  strings:
    $key_a1f5 = { f5 9d [2] 81 85 [2] c6 87 [2] 81 96 [2] cf 9a [2] c3 90 [2] d4 9b [2] cf d5 [2] f2 }

  condition:
    any of them
}