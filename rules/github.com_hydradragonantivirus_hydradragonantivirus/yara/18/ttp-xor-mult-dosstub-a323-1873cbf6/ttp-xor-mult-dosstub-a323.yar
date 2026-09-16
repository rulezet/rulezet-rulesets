rule TTP_XOR_MULT_DOSStub_a323 {
  strings:
    $key_a323 = { f7 4b [2] 83 53 [2] c4 51 [2] 83 40 [2] cd 4c [2] c1 46 [2] d6 4d [2] cd 03 [2] f0 }

  condition:
    any of them
}