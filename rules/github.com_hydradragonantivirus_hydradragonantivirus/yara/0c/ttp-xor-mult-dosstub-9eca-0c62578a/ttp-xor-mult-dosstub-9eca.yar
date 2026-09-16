rule TTP_XOR_MULT_DOSStub_9eca {
  strings:
    $key_9eca = { ca a2 [2] be ba [2] f9 b8 [2] be a9 [2] f0 a5 [2] fc af [2] eb a4 [2] f0 ea [2] cd }

  condition:
    any of them
}