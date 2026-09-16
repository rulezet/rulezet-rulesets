rule TTP_XOR_MULT_DOSStub_a32d {
  strings:
    $key_a32d = { f7 45 [2] 83 5d [2] c4 5f [2] 83 4e [2] cd 42 [2] c1 48 [2] d6 43 [2] cd 0d [2] f0 }

  condition:
    any of them
}