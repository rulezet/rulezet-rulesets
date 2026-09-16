rule TTP_XOR_MULT_DOSStub_9e14 {
  strings:
    $key_9e14 = { ca 7c [2] be 64 [2] f9 66 [2] be 77 [2] f0 7b [2] fc 71 [2] eb 7a [2] f0 34 [2] cd }

  condition:
    any of them
}