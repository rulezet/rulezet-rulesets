rule TTP_XOR_MULT_DOSStub_9e93 {
  strings:
    $key_9e93 = { ca fb [2] be e3 [2] f9 e1 [2] be f0 [2] f0 fc [2] fc f6 [2] eb fd [2] f0 b3 [2] cd }

  condition:
    any of them
}