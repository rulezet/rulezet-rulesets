rule TTP_XOR_MULT_DOSStub_a3e8 {
  strings:
    $key_a3e8 = { f7 80 [2] 83 98 [2] c4 9a [2] 83 8b [2] cd 87 [2] c1 8d [2] d6 86 [2] cd c8 [2] f0 }

  condition:
    any of them
}