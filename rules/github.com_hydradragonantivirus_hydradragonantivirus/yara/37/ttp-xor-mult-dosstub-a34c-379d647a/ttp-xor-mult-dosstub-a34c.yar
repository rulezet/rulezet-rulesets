rule TTP_XOR_MULT_DOSStub_a34c {
  strings:
    $key_a34c = { f7 24 [2] 83 3c [2] c4 3e [2] 83 2f [2] cd 23 [2] c1 29 [2] d6 22 [2] cd 6c [2] f0 }

  condition:
    any of them
}