rule TTP_XOR_MULT_DOSStub_9e4f {
  strings:
    $key_9e4f = { ca 27 [2] be 3f [2] f9 3d [2] be 2c [2] f0 20 [2] fc 2a [2] eb 21 [2] f0 6f [2] cd }

  condition:
    any of them
}