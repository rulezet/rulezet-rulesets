rule TTP_XOR_MULT_DOSStub_a374 {
  strings:
    $key_a374 = { f7 1c [2] 83 04 [2] c4 06 [2] 83 17 [2] cd 1b [2] c1 11 [2] d6 1a [2] cd 54 [2] f0 }

  condition:
    any of them
}