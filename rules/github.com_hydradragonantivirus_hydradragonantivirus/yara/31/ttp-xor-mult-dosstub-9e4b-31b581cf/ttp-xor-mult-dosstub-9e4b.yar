rule TTP_XOR_MULT_DOSStub_9e4b {
  strings:
    $key_9e4b = { ca 23 [2] be 3b [2] f9 39 [2] be 28 [2] f0 24 [2] fc 2e [2] eb 25 [2] f0 6b [2] cd }

  condition:
    any of them
}