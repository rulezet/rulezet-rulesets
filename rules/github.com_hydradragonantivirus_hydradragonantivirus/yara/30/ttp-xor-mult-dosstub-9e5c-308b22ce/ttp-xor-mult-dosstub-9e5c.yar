rule TTP_XOR_MULT_DOSStub_9e5c {
  strings:
    $key_9e5c = { ca 34 [2] be 2c [2] f9 2e [2] be 3f [2] f0 33 [2] fc 39 [2] eb 32 [2] f0 7c [2] cd }

  condition:
    any of them
}