rule TTP_XOR_MULT_DOSStub_9e24 {
  strings:
    $key_9e24 = { ca 4c [2] be 54 [2] f9 56 [2] be 47 [2] f0 4b [2] fc 41 [2] eb 4a [2] f0 04 [2] cd }

  condition:
    any of them
}