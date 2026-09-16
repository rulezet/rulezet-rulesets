rule TTP_XOR_MULT_DOSStub_9e1f {
  strings:
    $key_9e1f = { ca 77 [2] be 6f [2] f9 6d [2] be 7c [2] f0 70 [2] fc 7a [2] eb 71 [2] f0 3f [2] cd }

  condition:
    any of them
}