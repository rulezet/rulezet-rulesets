rule TTP_XOR_MULT_DOSStub_9e9c {
  strings:
    $key_9e9c = { ca f4 [2] be ec [2] f9 ee [2] be ff [2] f0 f3 [2] fc f9 [2] eb f2 [2] f0 bc [2] cd }

  condition:
    any of them
}