rule TTP_XOR_MULT_DOSStub_a32b {
  strings:
    $key_a32b = { f7 43 [2] 83 5b [2] c4 59 [2] 83 48 [2] cd 44 [2] c1 4e [2] d6 45 [2] cd 0b [2] f0 }

  condition:
    any of them
}