rule TTP_XOR_MULT_DOSStub_9e16 {
  strings:
    $key_9e16 = { ca 7e [2] be 66 [2] f9 64 [2] be 75 [2] f0 79 [2] fc 73 [2] eb 78 [2] f0 36 [2] cd }

  condition:
    any of them
}