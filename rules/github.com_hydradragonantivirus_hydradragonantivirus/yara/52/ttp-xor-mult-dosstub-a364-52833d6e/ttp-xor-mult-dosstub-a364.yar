rule TTP_XOR_MULT_DOSStub_a364 {
  strings:
    $key_a364 = { f7 0c [2] 83 14 [2] c4 16 [2] 83 07 [2] cd 0b [2] c1 01 [2] d6 0a [2] cd 44 [2] f0 }

  condition:
    any of them
}