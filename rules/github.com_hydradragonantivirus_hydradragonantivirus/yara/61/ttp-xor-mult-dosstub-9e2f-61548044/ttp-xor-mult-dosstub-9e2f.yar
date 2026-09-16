rule TTP_XOR_MULT_DOSStub_9e2f {
  strings:
    $key_9e2f = { ca 47 [2] be 5f [2] f9 5d [2] be 4c [2] f0 40 [2] fc 4a [2] eb 41 [2] f0 0f [2] cd }

  condition:
    any of them
}