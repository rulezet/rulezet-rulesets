rule TTP_XOR_MULT_DOSStub_a34a {
  strings:
    $key_a34a = { f7 22 [2] 83 3a [2] c4 38 [2] 83 29 [2] cd 25 [2] c1 2f [2] d6 24 [2] cd 6a [2] f0 }

  condition:
    any of them
}