rule TTP_XOR_MULT_DOSStub_a3e5 {
  strings:
    $key_a3e5 = { f7 8d [2] 83 95 [2] c4 97 [2] 83 86 [2] cd 8a [2] c1 80 [2] d6 8b [2] cd c5 [2] f0 }

  condition:
    any of them
}