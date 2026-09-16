rule TTP_XOR_MULT_DOSStub_a377 {
  strings:
    $key_a377 = { f7 1f [2] 83 07 [2] c4 05 [2] 83 14 [2] cd 18 [2] c1 12 [2] d6 19 [2] cd 57 [2] f0 }

  condition:
    any of them
}