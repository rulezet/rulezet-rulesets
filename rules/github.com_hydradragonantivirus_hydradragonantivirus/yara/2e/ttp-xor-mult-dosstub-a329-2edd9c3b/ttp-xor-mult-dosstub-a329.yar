rule TTP_XOR_MULT_DOSStub_a329 {
  strings:
    $key_a329 = { f7 41 [2] 83 59 [2] c4 5b [2] 83 4a [2] cd 46 [2] c1 4c [2] d6 47 [2] cd 09 [2] f0 }

  condition:
    any of them
}