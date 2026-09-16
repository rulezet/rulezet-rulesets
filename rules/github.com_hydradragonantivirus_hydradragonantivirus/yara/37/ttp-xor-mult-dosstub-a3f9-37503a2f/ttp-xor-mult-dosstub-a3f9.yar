rule TTP_XOR_MULT_DOSStub_a3f9 {
  strings:
    $key_a3f9 = { f7 91 [2] 83 89 [2] c4 8b [2] 83 9a [2] cd 96 [2] c1 9c [2] d6 97 [2] cd d9 [2] f0 }

  condition:
    any of them
}