rule TTP_XOR_MULT_DOSStub_9ebe {
  strings:
    $key_9ebe = { ca d6 [2] be ce [2] f9 cc [2] be dd [2] f0 d1 [2] fc db [2] eb d0 [2] f0 9e [2] cd }

  condition:
    any of them
}