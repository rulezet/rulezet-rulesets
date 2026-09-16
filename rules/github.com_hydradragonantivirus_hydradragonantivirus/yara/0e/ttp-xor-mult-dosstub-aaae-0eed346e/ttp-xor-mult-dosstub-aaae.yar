rule TTP_XOR_MULT_DOSStub_aaae {
  strings:
    $key_aaae = { fe c6 [2] 8a de [2] cd dc [2] 8a cd [2] c4 c1 [2] c8 cb [2] df c0 [2] c4 8e [2] f9 }

  condition:
    any of them
}