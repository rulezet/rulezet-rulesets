rule TTP_XOR_MULT_DOSStub_a30a {
  strings:
    $key_a30a = { f7 62 [2] 83 7a [2] c4 78 [2] 83 69 [2] cd 65 [2] c1 6f [2] d6 64 [2] cd 2a [2] f0 }

  condition:
    any of them
}