rule TTP_XOR_MULT_DOSStub_9e26 {
  strings:
    $key_9e26 = { ca 4e [2] be 56 [2] f9 54 [2] be 45 [2] f0 49 [2] fc 43 [2] eb 48 [2] f0 06 [2] cd }

  condition:
    any of them
}