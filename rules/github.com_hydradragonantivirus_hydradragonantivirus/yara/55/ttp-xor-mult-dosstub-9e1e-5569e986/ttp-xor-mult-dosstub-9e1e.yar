rule TTP_XOR_MULT_DOSStub_9e1e {
  strings:
    $key_9e1e = { ca 76 [2] be 6e [2] f9 6c [2] be 7d [2] f0 71 [2] fc 7b [2] eb 70 [2] f0 3e [2] cd }

  condition:
    any of them
}