rule TTP_XOR_MULT_DOSStub_9e72 {
  strings:
    $key_9e72 = { ca 1a [2] be 02 [2] f9 00 [2] be 11 [2] f0 1d [2] fc 17 [2] eb 1c [2] f0 52 [2] cd }

  condition:
    any of them
}