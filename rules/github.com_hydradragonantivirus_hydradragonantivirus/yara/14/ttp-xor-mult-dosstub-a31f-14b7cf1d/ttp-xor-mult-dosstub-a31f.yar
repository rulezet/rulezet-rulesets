rule TTP_XOR_MULT_DOSStub_a31f {
  strings:
    $key_a31f = { f7 77 [2] 83 6f [2] c4 6d [2] 83 7c [2] cd 70 [2] c1 7a [2] d6 71 [2] cd 3f [2] f0 }

  condition:
    any of them
}