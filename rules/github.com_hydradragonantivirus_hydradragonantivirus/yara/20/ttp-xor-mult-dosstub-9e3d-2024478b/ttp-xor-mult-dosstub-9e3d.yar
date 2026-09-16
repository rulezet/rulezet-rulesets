rule TTP_XOR_MULT_DOSStub_9e3d {
  strings:
    $key_9e3d = { ca 55 [2] be 4d [2] f9 4f [2] be 5e [2] f0 52 [2] fc 58 [2] eb 53 [2] f0 1d [2] cd }

  condition:
    any of them
}