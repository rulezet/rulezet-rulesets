rule TTP_XOR_MULT_DOSStub_9ea3 {
  strings:
    $key_9ea3 = { ca cb [2] be d3 [2] f9 d1 [2] be c0 [2] f0 cc [2] fc c6 [2] eb cd [2] f0 83 [2] cd }

  condition:
    any of them
}