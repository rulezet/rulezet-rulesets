rule TTP_XOR_MULT_DOSStub_9e0d {
  strings:
    $key_9e0d = { ca 65 [2] be 7d [2] f9 7f [2] be 6e [2] f0 62 [2] fc 68 [2] eb 63 [2] f0 2d [2] cd }

  condition:
    any of them
}