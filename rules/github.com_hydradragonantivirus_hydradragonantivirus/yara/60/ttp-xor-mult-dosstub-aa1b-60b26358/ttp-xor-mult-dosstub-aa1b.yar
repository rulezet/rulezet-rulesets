rule TTP_XOR_MULT_DOSStub_aa1b {
  strings:
    $key_aa1b = { fe 73 [2] 8a 6b [2] cd 69 [2] 8a 78 [2] c4 74 [2] c8 7e [2] df 75 [2] c4 3b [2] f9 }

  condition:
    any of them
}