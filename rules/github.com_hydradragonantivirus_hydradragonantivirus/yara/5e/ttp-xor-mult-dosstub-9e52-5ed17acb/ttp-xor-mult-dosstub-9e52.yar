rule TTP_XOR_MULT_DOSStub_9e52 {
  strings:
    $key_9e52 = { ca 3a [2] be 22 [2] f9 20 [2] be 31 [2] f0 3d [2] fc 37 [2] eb 3c [2] f0 72 [2] cd }

  condition:
    any of them
}