rule TTP_XOR_MULT_DOSStub_9eb0 {
  strings:
    $key_9eb0 = { ca d8 [2] be c0 [2] f9 c2 [2] be d3 [2] f0 df [2] fc d5 [2] eb de [2] f0 90 [2] cd }

  condition:
    any of them
}