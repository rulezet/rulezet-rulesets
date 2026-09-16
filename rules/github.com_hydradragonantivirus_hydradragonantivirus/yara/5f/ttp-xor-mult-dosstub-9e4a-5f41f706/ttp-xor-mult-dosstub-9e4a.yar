rule TTP_XOR_MULT_DOSStub_9e4a {
  strings:
    $key_9e4a = { ca 22 [2] be 3a [2] f9 38 [2] be 29 [2] f0 25 [2] fc 2f [2] eb 24 [2] f0 6a [2] cd }

  condition:
    any of them
}