rule TTP_XOR_MULT_DOSStub_a114 {
  strings:
    $key_a114 = { f5 7c [2] 81 64 [2] c6 66 [2] 81 77 [2] cf 7b [2] c3 71 [2] d4 7a [2] cf 34 [2] f2 }

  condition:
    any of them
}