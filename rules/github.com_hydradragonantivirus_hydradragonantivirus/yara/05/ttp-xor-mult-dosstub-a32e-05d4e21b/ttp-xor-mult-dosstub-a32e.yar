rule TTP_XOR_MULT_DOSStub_a32e {
  strings:
    $key_a32e = { f7 46 [2] 83 5e [2] c4 5c [2] 83 4d [2] cd 41 [2] c1 4b [2] d6 40 [2] cd 0e [2] f0 }

  condition:
    any of them
}