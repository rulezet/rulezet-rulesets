rule TTP_XOR_MULT_DOSStub_a332 {
  strings:
    $key_a332 = { f7 5a [2] 83 42 [2] c4 40 [2] 83 51 [2] cd 5d [2] c1 57 [2] d6 5c [2] cd 12 [2] f0 }

  condition:
    any of them
}