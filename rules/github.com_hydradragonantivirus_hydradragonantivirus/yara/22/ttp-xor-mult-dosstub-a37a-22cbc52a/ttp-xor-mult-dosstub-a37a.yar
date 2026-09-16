rule TTP_XOR_MULT_DOSStub_a37a {
  strings:
    $key_a37a = { f7 12 [2] 83 0a [2] c4 08 [2] 83 19 [2] cd 15 [2] c1 1f [2] d6 14 [2] cd 5a [2] f0 }

  condition:
    any of them
}