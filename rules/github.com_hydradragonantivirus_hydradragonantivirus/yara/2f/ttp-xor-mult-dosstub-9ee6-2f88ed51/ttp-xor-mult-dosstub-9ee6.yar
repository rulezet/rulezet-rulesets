rule TTP_XOR_MULT_DOSStub_9ee6 {
  strings:
    $key_9ee6 = { ca 8e [2] be 96 [2] f9 94 [2] be 85 [2] f0 89 [2] fc 83 [2] eb 88 [2] f0 c6 [2] cd }

  condition:
    any of them
}