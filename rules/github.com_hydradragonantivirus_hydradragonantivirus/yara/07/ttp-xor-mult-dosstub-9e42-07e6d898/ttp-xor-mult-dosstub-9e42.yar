rule TTP_XOR_MULT_DOSStub_9e42 {
  strings:
    $key_9e42 = { ca 2a [2] be 32 [2] f9 30 [2] be 21 [2] f0 2d [2] fc 27 [2] eb 2c [2] f0 62 [2] cd }

  condition:
    any of them
}