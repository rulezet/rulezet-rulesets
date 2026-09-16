rule TTP_XOR_MULT_DOSStub_9ee7 {
  strings:
    $key_9ee7 = { ca 8f [2] be 97 [2] f9 95 [2] be 84 [2] f0 88 [2] fc 82 [2] eb 89 [2] f0 c7 [2] cd }

  condition:
    any of them
}