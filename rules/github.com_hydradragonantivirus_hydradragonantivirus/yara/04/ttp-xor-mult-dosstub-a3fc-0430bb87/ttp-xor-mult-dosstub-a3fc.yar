rule TTP_XOR_MULT_DOSStub_a3fc {
  strings:
    $key_a3fc = { f7 94 [2] 83 8c [2] c4 8e [2] 83 9f [2] cd 93 [2] c1 99 [2] d6 92 [2] cd dc [2] f0 }

  condition:
    any of them
}