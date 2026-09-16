rule TTP_XOR_MULT_DOSStub_9e07 {
  strings:
    $key_9e07 = { ca 6f [2] be 77 [2] f9 75 [2] be 64 [2] f0 68 [2] fc 62 [2] eb 69 [2] f0 27 [2] cd }

  condition:
    any of them
}