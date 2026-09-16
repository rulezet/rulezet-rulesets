rule TTP_XOR_MULT_DOSStub_9e28 {
  strings:
    $key_9e28 = { ca 40 [2] be 58 [2] f9 5a [2] be 4b [2] f0 47 [2] fc 4d [2] eb 46 [2] f0 08 [2] cd }

  condition:
    any of them
}