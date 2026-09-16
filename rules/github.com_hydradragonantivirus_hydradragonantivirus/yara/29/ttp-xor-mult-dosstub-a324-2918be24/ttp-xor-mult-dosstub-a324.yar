rule TTP_XOR_MULT_DOSStub_a324 {
  strings:
    $key_a324 = { f7 4c [2] 83 54 [2] c4 56 [2] 83 47 [2] cd 4b [2] c1 41 [2] d6 4a [2] cd 04 [2] f0 }

  condition:
    any of them
}