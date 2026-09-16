rule TTP_XOR_MULT_DOSStub_a34d {
  strings:
    $key_a34d = { f7 25 [2] 83 3d [2] c4 3f [2] 83 2e [2] cd 22 [2] c1 28 [2] d6 23 [2] cd 6d [2] f0 }

  condition:
    any of them
}