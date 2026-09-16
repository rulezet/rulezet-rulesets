rule TTP_XOR_MULT_DOSStub_9e04 {
  strings:
    $key_9e04 = { ca 6c [2] be 74 [2] f9 76 [2] be 67 [2] f0 6b [2] fc 61 [2] eb 6a [2] f0 24 [2] cd }

  condition:
    any of them
}