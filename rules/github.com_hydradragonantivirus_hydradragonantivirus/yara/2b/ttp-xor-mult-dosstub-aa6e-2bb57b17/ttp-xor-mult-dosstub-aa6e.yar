rule TTP_XOR_MULT_DOSStub_aa6e {
  strings:
    $key_aa6e = { fe 06 [2] 8a 1e [2] cd 1c [2] 8a 0d [2] c4 01 [2] c8 0b [2] df 00 [2] c4 4e [2] f9 }

  condition:
    any of them
}