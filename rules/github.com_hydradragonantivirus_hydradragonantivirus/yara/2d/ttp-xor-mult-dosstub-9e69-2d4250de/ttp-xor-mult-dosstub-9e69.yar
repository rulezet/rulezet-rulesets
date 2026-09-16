rule TTP_XOR_MULT_DOSStub_9e69 {
  strings:
    $key_9e69 = { ca 01 [2] be 19 [2] f9 1b [2] be 0a [2] f0 06 [2] fc 0c [2] eb 07 [2] f0 49 [2] cd }

  condition:
    any of them
}