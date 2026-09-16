rule TTP_XOR_MULT_DOSStub_9eba {
  strings:
    $key_9eba = { ca d2 [2] be ca [2] f9 c8 [2] be d9 [2] f0 d5 [2] fc df [2] eb d4 [2] f0 9a [2] cd }

  condition:
    any of them
}