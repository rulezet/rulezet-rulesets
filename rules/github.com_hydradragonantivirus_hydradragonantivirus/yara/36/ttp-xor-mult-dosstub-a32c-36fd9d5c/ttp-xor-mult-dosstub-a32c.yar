rule TTP_XOR_MULT_DOSStub_a32c {
  strings:
    $key_a32c = { f7 44 [2] 83 5c [2] c4 5e [2] 83 4f [2] cd 43 [2] c1 49 [2] d6 42 [2] cd 0c [2] f0 }

  condition:
    any of them
}