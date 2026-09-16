rule TTP_XOR_MULT_DOSStub_aabd {
  strings:
    $key_aabd = { fe d5 [2] 8a cd [2] cd cf [2] 8a de [2] c4 d2 [2] c8 d8 [2] df d3 [2] c4 9d [2] f9 }

  condition:
    any of them
}