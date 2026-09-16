rule TTP_XOR_MULT_DOSStub_a3e2 {
  strings:
    $key_a3e2 = { f7 8a [2] 83 92 [2] c4 90 [2] 83 81 [2] cd 8d [2] c1 87 [2] d6 8c [2] cd c2 [2] f0 }

  condition:
    any of them
}