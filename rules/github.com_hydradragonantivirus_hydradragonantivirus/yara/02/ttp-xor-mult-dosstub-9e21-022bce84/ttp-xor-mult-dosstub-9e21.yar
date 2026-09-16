rule TTP_XOR_MULT_DOSStub_9e21 {
  strings:
    $key_9e21 = { ca 49 [2] be 51 [2] f9 53 [2] be 42 [2] f0 4e [2] fc 44 [2] eb 4f [2] f0 01 [2] cd }

  condition:
    any of them
}