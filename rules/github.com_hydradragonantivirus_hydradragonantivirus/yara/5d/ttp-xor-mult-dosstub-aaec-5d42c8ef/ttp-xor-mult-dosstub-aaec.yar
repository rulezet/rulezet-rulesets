rule TTP_XOR_MULT_DOSStub_aaec {
  strings:
    $key_aaec = { fe 84 [2] 8a 9c [2] cd 9e [2] 8a 8f [2] c4 83 [2] c8 89 [2] df 82 [2] c4 cc [2] f9 }

  condition:
    any of them
}