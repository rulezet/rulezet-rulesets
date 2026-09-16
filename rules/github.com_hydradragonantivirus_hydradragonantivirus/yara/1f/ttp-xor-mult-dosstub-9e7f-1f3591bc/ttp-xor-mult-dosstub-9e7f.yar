rule TTP_XOR_MULT_DOSStub_9e7f {
  strings:
    $key_9e7f = { ca 17 [2] be 0f [2] f9 0d [2] be 1c [2] f0 10 [2] fc 1a [2] eb 11 [2] f0 5f [2] cd }

  condition:
    any of them
}