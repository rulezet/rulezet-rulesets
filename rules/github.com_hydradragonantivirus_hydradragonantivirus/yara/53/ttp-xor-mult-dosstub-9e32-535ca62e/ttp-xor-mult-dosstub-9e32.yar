rule TTP_XOR_MULT_DOSStub_9e32 {
  strings:
    $key_9e32 = { ca 5a [2] be 42 [2] f9 40 [2] be 51 [2] f0 5d [2] fc 57 [2] eb 5c [2] f0 12 [2] cd }

  condition:
    any of them
}