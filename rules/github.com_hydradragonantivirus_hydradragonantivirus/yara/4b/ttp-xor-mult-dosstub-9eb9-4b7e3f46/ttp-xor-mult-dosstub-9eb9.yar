rule TTP_XOR_MULT_DOSStub_9eb9 {
  strings:
    $key_9eb9 = { ca d1 [2] be c9 [2] f9 cb [2] be da [2] f0 d6 [2] fc dc [2] eb d7 [2] f0 99 [2] cd }

  condition:
    any of them
}