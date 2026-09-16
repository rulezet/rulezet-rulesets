rule TTP_XOR_MULT_DOSStub_a1f8 {
  strings:
    $key_a1f8 = { f5 90 [2] 81 88 [2] c6 8a [2] 81 9b [2] cf 97 [2] c3 9d [2] d4 96 [2] cf d8 [2] f2 }

  condition:
    any of them
}