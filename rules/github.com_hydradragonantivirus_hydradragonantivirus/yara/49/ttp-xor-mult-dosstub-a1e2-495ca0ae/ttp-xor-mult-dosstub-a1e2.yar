rule TTP_XOR_MULT_DOSStub_a1e2 {
  strings:
    $key_a1e2 = { f5 8a [2] 81 92 [2] c6 90 [2] 81 81 [2] cf 8d [2] c3 87 [2] d4 8c [2] cf c2 [2] f2 }

  condition:
    any of them
}