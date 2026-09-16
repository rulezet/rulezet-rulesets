rule TTP_XOR_MULT_DOSStub_9e03 {
  strings:
    $key_9e03 = { ca 6b [2] be 73 [2] f9 71 [2] be 60 [2] f0 6c [2] fc 66 [2] eb 6d [2] f0 23 [2] cd }

  condition:
    any of them
}