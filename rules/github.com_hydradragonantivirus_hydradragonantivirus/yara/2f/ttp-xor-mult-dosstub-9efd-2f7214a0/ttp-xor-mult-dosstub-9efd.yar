rule TTP_XOR_MULT_DOSStub_9efd {
  strings:
    $key_9efd = { ca 95 [2] be 8d [2] f9 8f [2] be 9e [2] f0 92 [2] fc 98 [2] eb 93 [2] f0 dd [2] cd }

  condition:
    any of them
}