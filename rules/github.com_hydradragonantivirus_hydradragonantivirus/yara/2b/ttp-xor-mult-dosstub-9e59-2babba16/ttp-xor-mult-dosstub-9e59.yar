rule TTP_XOR_MULT_DOSStub_9e59 {
  strings:
    $key_9e59 = { ca 31 [2] be 29 [2] f9 2b [2] be 3a [2] f0 36 [2] fc 3c [2] eb 37 [2] f0 79 [2] cd }

  condition:
    any of them
}