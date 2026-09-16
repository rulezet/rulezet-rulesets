rule TTP_XOR_MULT_DOSStub_aa3e {
  strings:
    $key_aa3e = { fe 56 [2] 8a 4e [2] cd 4c [2] 8a 5d [2] c4 51 [2] c8 5b [2] df 50 [2] c4 1e [2] f9 }

  condition:
    any of them
}