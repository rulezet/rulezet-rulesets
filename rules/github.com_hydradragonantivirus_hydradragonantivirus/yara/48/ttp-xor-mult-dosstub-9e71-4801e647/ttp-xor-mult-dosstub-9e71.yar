rule TTP_XOR_MULT_DOSStub_9e71 {
  strings:
    $key_9e71 = { ca 19 [2] be 01 [2] f9 03 [2] be 12 [2] f0 1e [2] fc 14 [2] eb 1f [2] f0 51 [2] cd }

  condition:
    any of them
}