rule TTP_XOR_MULT_DOSStub_9e7d {
  strings:
    $key_9e7d = { ca 15 [2] be 0d [2] f9 0f [2] be 1e [2] f0 12 [2] fc 18 [2] eb 13 [2] f0 5d [2] cd }

  condition:
    any of them
}