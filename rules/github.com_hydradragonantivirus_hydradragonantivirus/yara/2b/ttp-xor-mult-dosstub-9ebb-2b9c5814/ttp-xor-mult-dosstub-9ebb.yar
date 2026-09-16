rule TTP_XOR_MULT_DOSStub_9ebb {
  strings:
    $key_9ebb = { ca d3 [2] be cb [2] f9 c9 [2] be d8 [2] f0 d4 [2] fc de [2] eb d5 [2] f0 9b [2] cd }

  condition:
    any of them
}