rule TTP_XOR_MULT_DOSStub_9e3f {
  strings:
    $key_9e3f = { ca 57 [2] be 4f [2] f9 4d [2] be 5c [2] f0 50 [2] fc 5a [2] eb 51 [2] f0 1f [2] cd }

  condition:
    any of them
}