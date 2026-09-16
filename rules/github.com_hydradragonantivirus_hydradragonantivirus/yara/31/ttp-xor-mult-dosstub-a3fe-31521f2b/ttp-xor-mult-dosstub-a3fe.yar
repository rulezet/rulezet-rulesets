rule TTP_XOR_MULT_DOSStub_a3fe {
  strings:
    $key_a3fe = { f7 96 [2] 83 8e [2] c4 8c [2] 83 9d [2] cd 91 [2] c1 9b [2] d6 90 [2] cd de [2] f0 }

  condition:
    any of them
}