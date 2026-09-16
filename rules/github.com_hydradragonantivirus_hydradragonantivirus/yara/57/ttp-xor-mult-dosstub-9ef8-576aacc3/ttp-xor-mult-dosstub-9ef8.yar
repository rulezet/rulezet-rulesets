rule TTP_XOR_MULT_DOSStub_9ef8 {
  strings:
    $key_9ef8 = { ca 90 [2] be 88 [2] f9 8a [2] be 9b [2] f0 97 [2] fc 9d [2] eb 96 [2] f0 d8 [2] cd }

  condition:
    any of them
}