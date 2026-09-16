rule TTP_XOR_MULT_DOSStub_9e17 {
  strings:
    $key_9e17 = { ca 7f [2] be 67 [2] f9 65 [2] be 74 [2] f0 78 [2] fc 72 [2] eb 79 [2] f0 37 [2] cd }

  condition:
    any of them
}