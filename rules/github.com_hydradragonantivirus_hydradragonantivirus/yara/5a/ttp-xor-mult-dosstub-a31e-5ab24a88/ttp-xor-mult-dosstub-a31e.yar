rule TTP_XOR_MULT_DOSStub_a31e {
  strings:
    $key_a31e = { f7 76 [2] 83 6e [2] c4 6c [2] 83 7d [2] cd 71 [2] c1 7b [2] d6 70 [2] cd 3e [2] f0 }

  condition:
    any of them
}