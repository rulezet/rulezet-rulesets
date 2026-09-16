rule TTP_XOR_MULT_DOSStub_bbc8 {
  strings:
    $key_bbc8 = { ef a0 [2] 9b b8 [2] dc ba [2] 9b ab [2] d5 a7 [2] d9 ad [2] ce a6 [2] d5 e8 [2] e8 }

  condition:
    any of them
}