rule TTP_XOR_MULT_DOSStub_9e76 {
  strings:
    $key_9e76 = { ca 1e [2] be 06 [2] f9 04 [2] be 15 [2] f0 19 [2] fc 13 [2] eb 18 [2] f0 56 [2] cd }

  condition:
    any of them
}