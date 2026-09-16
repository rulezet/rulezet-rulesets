rule TTP_XOR_MULT_DOSStub_a322 {
  strings:
    $key_a322 = { f7 4a [2] 83 52 [2] c4 50 [2] 83 41 [2] cd 4d [2] c1 47 [2] d6 4c [2] cd 02 [2] f0 }

  condition:
    any of them
}