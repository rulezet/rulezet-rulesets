rule TTP_XOR_MULT_DOSStub_9eb1 {
  strings:
    $key_9eb1 = { ca d9 [2] be c1 [2] f9 c3 [2] be d2 [2] f0 de [2] fc d4 [2] eb df [2] f0 91 [2] cd }

  condition:
    any of them
}