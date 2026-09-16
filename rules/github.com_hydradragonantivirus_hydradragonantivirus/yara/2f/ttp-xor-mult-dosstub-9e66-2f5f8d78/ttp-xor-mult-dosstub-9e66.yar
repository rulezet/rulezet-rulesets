rule TTP_XOR_MULT_DOSStub_9e66 {
  strings:
    $key_9e66 = { ca 0e [2] be 16 [2] f9 14 [2] be 05 [2] f0 09 [2] fc 03 [2] eb 08 [2] f0 46 [2] cd }

  condition:
    any of them
}