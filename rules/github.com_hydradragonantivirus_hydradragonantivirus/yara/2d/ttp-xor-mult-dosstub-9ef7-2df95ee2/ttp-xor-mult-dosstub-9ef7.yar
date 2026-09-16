rule TTP_XOR_MULT_DOSStub_9ef7 {
  strings:
    $key_9ef7 = { ca 9f [2] be 87 [2] f9 85 [2] be 94 [2] f0 98 [2] fc 92 [2] eb 99 [2] f0 d7 [2] cd }

  condition:
    any of them
}