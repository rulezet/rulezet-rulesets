rule TTP_XOR_MULT_DOSStub_9ea6 {
  strings:
    $key_9ea6 = { ca ce [2] be d6 [2] f9 d4 [2] be c5 [2] f0 c9 [2] fc c3 [2] eb c8 [2] f0 86 [2] cd }

  condition:
    any of them
}