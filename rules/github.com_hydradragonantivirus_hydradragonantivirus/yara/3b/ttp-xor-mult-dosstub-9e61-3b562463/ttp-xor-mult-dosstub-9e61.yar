rule TTP_XOR_MULT_DOSStub_9e61 {
  strings:
    $key_9e61 = { ca 09 [2] be 11 [2] f9 13 [2] be 02 [2] f0 0e [2] fc 04 [2] eb 0f [2] f0 41 [2] cd }

  condition:
    any of them
}