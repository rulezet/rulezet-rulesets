rule TTP_XOR_MULT_DOSStub_9efc {
  strings:
    $key_9efc = { ca 94 [2] be 8c [2] f9 8e [2] be 9f [2] f0 93 [2] fc 99 [2] eb 92 [2] f0 dc [2] cd }

  condition:
    any of them
}