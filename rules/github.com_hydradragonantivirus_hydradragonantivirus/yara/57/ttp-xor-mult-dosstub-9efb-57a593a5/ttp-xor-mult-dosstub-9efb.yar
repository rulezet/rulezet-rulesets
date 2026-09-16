rule TTP_XOR_MULT_DOSStub_9efb {
  strings:
    $key_9efb = { ca 93 [2] be 8b [2] f9 89 [2] be 98 [2] f0 94 [2] fc 9e [2] eb 95 [2] f0 db [2] cd }

  condition:
    any of them
}