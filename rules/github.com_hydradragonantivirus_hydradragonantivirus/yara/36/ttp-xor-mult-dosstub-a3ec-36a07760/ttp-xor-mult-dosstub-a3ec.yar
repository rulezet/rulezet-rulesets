rule TTP_XOR_MULT_DOSStub_a3ec {
  strings:
    $key_a3ec = { f7 84 [2] 83 9c [2] c4 9e [2] 83 8f [2] cd 83 [2] c1 89 [2] d6 82 [2] cd cc [2] f0 }

  condition:
    any of them
}