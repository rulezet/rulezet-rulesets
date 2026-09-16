rule TTP_XOR_MULT_DOSStub_9e09 {
  strings:
    $key_9e09 = { ca 61 [2] be 79 [2] f9 7b [2] be 6a [2] f0 66 [2] fc 6c [2] eb 67 [2] f0 29 [2] cd }

  condition:
    any of them
}