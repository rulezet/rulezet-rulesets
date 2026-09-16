rule TTP_XOR_MULT_DOSStub_9e0b {
  strings:
    $key_9e0b = { ca 63 [2] be 7b [2] f9 79 [2] be 68 [2] f0 64 [2] fc 6e [2] eb 65 [2] f0 2b [2] cd }

  condition:
    any of them
}