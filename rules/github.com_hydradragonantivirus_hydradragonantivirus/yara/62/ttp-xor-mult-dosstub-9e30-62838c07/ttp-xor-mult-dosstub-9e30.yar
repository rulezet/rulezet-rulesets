rule TTP_XOR_MULT_DOSStub_9e30 {
  strings:
    $key_9e30 = { ca 58 [2] be 40 [2] f9 42 [2] be 53 [2] f0 5f [2] fc 55 [2] eb 5e [2] f0 10 [2] cd }

  condition:
    any of them
}