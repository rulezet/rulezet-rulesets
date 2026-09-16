rule TTP_XOR_MULT_DOSStub_a33d {
  strings:
    $key_a33d = { f7 55 [2] 83 4d [2] c4 4f [2] 83 5e [2] cd 52 [2] c1 58 [2] d6 53 [2] cd 1d [2] f0 }

  condition:
    any of them
}