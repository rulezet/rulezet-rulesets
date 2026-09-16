rule TTP_XOR_MULT_DOSStub_a36b {
  strings:
    $key_a36b = { f7 03 [2] 83 1b [2] c4 19 [2] 83 08 [2] cd 04 [2] c1 0e [2] d6 05 [2] cd 4b [2] f0 }

  condition:
    any of them
}