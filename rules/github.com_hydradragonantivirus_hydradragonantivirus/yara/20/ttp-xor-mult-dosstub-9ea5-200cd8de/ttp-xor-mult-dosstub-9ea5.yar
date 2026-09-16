rule TTP_XOR_MULT_DOSStub_9ea5 {
  strings:
    $key_9ea5 = { ca cd [2] be d5 [2] f9 d7 [2] be c6 [2] f0 ca [2] fc c0 [2] eb cb [2] f0 85 [2] cd }

  condition:
    any of them
}