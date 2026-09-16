rule TTP_XOR_MULT_DOSStub_9e41 {
  strings:
    $key_9e41 = { ca 29 [2] be 31 [2] f9 33 [2] be 22 [2] f0 2e [2] fc 24 [2] eb 2f [2] f0 61 [2] cd }

  condition:
    any of them
}