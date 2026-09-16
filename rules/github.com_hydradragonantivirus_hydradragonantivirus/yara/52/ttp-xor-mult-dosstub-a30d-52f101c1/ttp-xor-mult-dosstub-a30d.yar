rule TTP_XOR_MULT_DOSStub_a30d {
  strings:
    $key_a30d = { f7 65 [2] 83 7d [2] c4 7f [2] 83 6e [2] cd 62 [2] c1 68 [2] d6 63 [2] cd 2d [2] f0 }

  condition:
    any of them
}