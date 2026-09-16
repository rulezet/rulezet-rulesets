rule TTP_XOR_MULT_DOSStub_a7e2 {
  strings:
    $key_a7e2 = { f3 8a [2] 87 92 [2] c0 90 [2] 87 81 [2] c9 8d [2] c5 87 [2] d2 8c [2] c9 c2 [2] f4 }

  condition:
    any of them
}