rule TTP_XOR_MULT_DOSStub_a35c {
  strings:
    $key_a35c = { f7 34 [2] 83 2c [2] c4 2e [2] 83 3f [2] cd 33 [2] c1 39 [2] d6 32 [2] cd 7c [2] f0 }

  condition:
    any of them
}