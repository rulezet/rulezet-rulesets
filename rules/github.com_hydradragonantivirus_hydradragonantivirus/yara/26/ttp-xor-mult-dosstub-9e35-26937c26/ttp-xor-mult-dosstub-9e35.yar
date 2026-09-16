rule TTP_XOR_MULT_DOSStub_9e35 {
  strings:
    $key_9e35 = { ca 5d [2] be 45 [2] f9 47 [2] be 56 [2] f0 5a [2] fc 50 [2] eb 5b [2] f0 15 [2] cd }

  condition:
    any of them
}