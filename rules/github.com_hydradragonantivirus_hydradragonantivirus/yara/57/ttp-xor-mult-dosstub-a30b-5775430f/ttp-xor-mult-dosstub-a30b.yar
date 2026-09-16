rule TTP_XOR_MULT_DOSStub_a30b {
  strings:
    $key_a30b = { f7 63 [2] 83 7b [2] c4 79 [2] 83 68 [2] cd 64 [2] c1 6e [2] d6 65 [2] cd 2b [2] f0 }

  condition:
    any of them
}