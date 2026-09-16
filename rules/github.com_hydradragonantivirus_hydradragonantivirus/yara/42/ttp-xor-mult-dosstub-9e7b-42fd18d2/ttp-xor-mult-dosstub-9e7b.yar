rule TTP_XOR_MULT_DOSStub_9e7b {
  strings:
    $key_9e7b = { ca 13 [2] be 0b [2] f9 09 [2] be 18 [2] f0 14 [2] fc 1e [2] eb 15 [2] f0 5b [2] cd }

  condition:
    any of them
}