rule TTP_XOR_MULT_DOSStub_a334 {
  strings:
    $key_a334 = { f7 5c [2] 83 44 [2] c4 46 [2] 83 57 [2] cd 5b [2] c1 51 [2] d6 5a [2] cd 14 [2] f0 }

  condition:
    any of them
}