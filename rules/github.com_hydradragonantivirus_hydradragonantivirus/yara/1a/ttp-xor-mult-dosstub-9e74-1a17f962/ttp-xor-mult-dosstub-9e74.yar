rule TTP_XOR_MULT_DOSStub_9e74 {
  strings:
    $key_9e74 = { ca 1c [2] be 04 [2] f9 06 [2] be 17 [2] f0 1b [2] fc 11 [2] eb 1a [2] f0 54 [2] cd }

  condition:
    any of them
}