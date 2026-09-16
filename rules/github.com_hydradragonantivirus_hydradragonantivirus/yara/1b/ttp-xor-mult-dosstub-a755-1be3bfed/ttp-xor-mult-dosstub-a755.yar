rule TTP_XOR_MULT_DOSStub_a755 {
  strings:
    $key_a755 = { f3 3d [2] 87 25 [2] c0 27 [2] 87 36 [2] c9 3a [2] c5 30 [2] d2 3b [2] c9 75 [2] f4 }

  condition:
    any of them
}