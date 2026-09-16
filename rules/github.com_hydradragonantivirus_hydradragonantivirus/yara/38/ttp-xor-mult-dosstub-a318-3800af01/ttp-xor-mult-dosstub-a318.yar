rule TTP_XOR_MULT_DOSStub_a318 {
  strings:
    $key_a318 = { f7 70 [2] 83 68 [2] c4 6a [2] 83 7b [2] cd 77 [2] c1 7d [2] d6 76 [2] cd 38 [2] f0 }

  condition:
    any of them
}