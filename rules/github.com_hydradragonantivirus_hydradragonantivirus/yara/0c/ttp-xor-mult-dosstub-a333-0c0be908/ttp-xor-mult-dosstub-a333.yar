rule TTP_XOR_MULT_DOSStub_a333 {
  strings:
    $key_a333 = { f7 5b [2] 83 43 [2] c4 41 [2] 83 50 [2] cd 5c [2] c1 56 [2] d6 5d [2] cd 13 [2] f0 }

  condition:
    any of them
}