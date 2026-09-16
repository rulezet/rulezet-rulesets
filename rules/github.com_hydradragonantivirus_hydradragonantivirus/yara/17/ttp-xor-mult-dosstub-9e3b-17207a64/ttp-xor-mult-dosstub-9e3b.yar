rule TTP_XOR_MULT_DOSStub_9e3b {
  strings:
    $key_9e3b = { ca 53 [2] be 4b [2] f9 49 [2] be 58 [2] f0 54 [2] fc 5e [2] eb 55 [2] f0 1b [2] cd }

  condition:
    any of them
}