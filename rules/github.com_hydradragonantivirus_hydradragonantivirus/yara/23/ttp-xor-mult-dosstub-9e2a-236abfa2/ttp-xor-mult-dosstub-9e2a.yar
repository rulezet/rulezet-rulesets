rule TTP_XOR_MULT_DOSStub_9e2a {
  strings:
    $key_9e2a = { ca 42 [2] be 5a [2] f9 58 [2] be 49 [2] f0 45 [2] fc 4f [2] eb 44 [2] f0 0a [2] cd }

  condition:
    any of them
}