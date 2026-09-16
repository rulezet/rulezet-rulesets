rule TTP_XOR_MULT_DOSStub_9e33 {
  strings:
    $key_9e33 = { ca 5b [2] be 43 [2] f9 41 [2] be 50 [2] f0 5c [2] fc 56 [2] eb 5d [2] f0 13 [2] cd }

  condition:
    any of them
}