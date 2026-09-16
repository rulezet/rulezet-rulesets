rule TTP_XOR_MULT_DOSStub_a37f {
  strings:
    $key_a37f = { f7 17 [2] 83 0f [2] c4 0d [2] 83 1c [2] cd 10 [2] c1 1a [2] d6 11 [2] cd 5f [2] f0 }

  condition:
    any of them
}