rule TTP_XOR_MULT_DOSStub_a37c {
  strings:
    $key_a37c = { f7 14 [2] 83 0c [2] c4 0e [2] 83 1f [2] cd 13 [2] c1 19 [2] d6 12 [2] cd 5c [2] f0 }

  condition:
    any of them
}