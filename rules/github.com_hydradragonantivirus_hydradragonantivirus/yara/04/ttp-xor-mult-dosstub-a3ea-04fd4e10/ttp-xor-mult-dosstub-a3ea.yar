rule TTP_XOR_MULT_DOSStub_a3ea {
  strings:
    $key_a3ea = { f7 82 [2] 83 9a [2] c4 98 [2] 83 89 [2] cd 85 [2] c1 8f [2] d6 84 [2] cd ca [2] f0 }

  condition:
    any of them
}