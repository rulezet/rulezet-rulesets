rule TTP_XOR_MULT_DOSStub_a155 {
  strings:
    $key_a155 = { f5 3d [2] 81 25 [2] c6 27 [2] 81 36 [2] cf 3a [2] c3 30 [2] d4 3b [2] cf 75 [2] f2 }

  condition:
    any of them
}