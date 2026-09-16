rule TTP_XOR_MULT_DOSStub_9e08 {
  strings:
    $key_9e08 = { ca 60 [2] be 78 [2] f9 7a [2] be 6b [2] f0 67 [2] fc 6d [2] eb 66 [2] f0 28 [2] cd }

  condition:
    any of them
}