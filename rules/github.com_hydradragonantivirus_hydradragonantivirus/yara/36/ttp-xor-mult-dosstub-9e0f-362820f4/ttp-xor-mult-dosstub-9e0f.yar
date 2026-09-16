rule TTP_XOR_MULT_DOSStub_9e0f {
  strings:
    $key_9e0f = { ca 67 [2] be 7f [2] f9 7d [2] be 6c [2] f0 60 [2] fc 6a [2] eb 61 [2] f0 2f [2] cd }

  condition:
    any of them
}