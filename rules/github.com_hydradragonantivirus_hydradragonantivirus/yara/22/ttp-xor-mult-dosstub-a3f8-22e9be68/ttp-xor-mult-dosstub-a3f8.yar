rule TTP_XOR_MULT_DOSStub_a3f8 {
  strings:
    $key_a3f8 = { f7 90 [2] 83 88 [2] c4 8a [2] 83 9b [2] cd 97 [2] c1 9d [2] d6 96 [2] cd d8 [2] f0 }

  condition:
    any of them
}