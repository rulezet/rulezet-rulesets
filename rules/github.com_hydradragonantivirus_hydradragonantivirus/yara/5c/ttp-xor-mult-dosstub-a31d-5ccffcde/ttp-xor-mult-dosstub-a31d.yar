rule TTP_XOR_MULT_DOSStub_a31d {
  strings:
    $key_a31d = { f7 75 [2] 83 6d [2] c4 6f [2] 83 7e [2] cd 72 [2] c1 78 [2] d6 73 [2] cd 3d [2] f0 }

  condition:
    any of them
}