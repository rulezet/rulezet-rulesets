rule TTP_XOR_MULT_DOSStub_9ea7 {
  strings:
    $key_9ea7 = { ca cf [2] be d7 [2] f9 d5 [2] be c4 [2] f0 c8 [2] fc c2 [2] eb c9 [2] f0 87 [2] cd }

  condition:
    any of them
}