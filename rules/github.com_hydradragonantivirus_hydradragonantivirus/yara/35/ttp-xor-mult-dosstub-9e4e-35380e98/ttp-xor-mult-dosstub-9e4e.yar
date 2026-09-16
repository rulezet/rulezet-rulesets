rule TTP_XOR_MULT_DOSStub_9e4e {
  strings:
    $key_9e4e = { ca 26 [2] be 3e [2] f9 3c [2] be 2d [2] f0 21 [2] fc 2b [2] eb 20 [2] f0 6e [2] cd }

  condition:
    any of them
}