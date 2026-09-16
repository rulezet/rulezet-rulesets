rule TTP_XOR_MULT_DOSStub_a353 {
  strings:
    $key_a353 = { f7 3b [2] 83 23 [2] c4 21 [2] 83 30 [2] cd 3c [2] c1 36 [2] d6 3d [2] cd 73 [2] f0 }

  condition:
    any of them
}