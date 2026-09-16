rule TTP_XOR_MULT_DOSStub_9e3a {
  strings:
    $key_9e3a = { ca 52 [2] be 4a [2] f9 48 [2] be 59 [2] f0 55 [2] fc 5f [2] eb 54 [2] f0 1a [2] cd }

  condition:
    any of them
}