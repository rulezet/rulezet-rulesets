rule TTP_XOR_MULT_DOSStub_9e39 {
  strings:
    $key_9e39 = { ca 51 [2] be 49 [2] f9 4b [2] be 5a [2] f0 56 [2] fc 5c [2] eb 57 [2] f0 19 [2] cd }

  condition:
    any of them
}