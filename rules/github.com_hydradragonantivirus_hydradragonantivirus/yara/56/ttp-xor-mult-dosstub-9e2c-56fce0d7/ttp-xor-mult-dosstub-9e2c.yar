rule TTP_XOR_MULT_DOSStub_9e2c {
  strings:
    $key_9e2c = { ca 44 [2] be 5c [2] f9 5e [2] be 4f [2] f0 43 [2] fc 49 [2] eb 42 [2] f0 0c [2] cd }

  condition:
    any of them
}