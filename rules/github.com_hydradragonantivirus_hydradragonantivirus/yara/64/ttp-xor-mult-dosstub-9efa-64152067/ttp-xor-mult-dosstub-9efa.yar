rule TTP_XOR_MULT_DOSStub_9efa {
  strings:
    $key_9efa = { ca 92 [2] be 8a [2] f9 88 [2] be 99 [2] f0 95 [2] fc 9f [2] eb 94 [2] f0 da [2] cd }

  condition:
    any of them
}