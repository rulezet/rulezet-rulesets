rule TTP_XOR_MULT_DOSStub_a35b {
  strings:
    $key_a35b = { f7 33 [2] 83 2b [2] c4 29 [2] 83 38 [2] cd 34 [2] c1 3e [2] d6 35 [2] cd 7b [2] f0 }

  condition:
    any of them
}