rule TTP_XOR_MULT_DOSStub_9ee5 {
  strings:
    $key_9ee5 = { ca 8d [2] be 95 [2] f9 97 [2] be 86 [2] f0 8a [2] fc 80 [2] eb 8b [2] f0 c5 [2] cd }

  condition:
    any of them
}