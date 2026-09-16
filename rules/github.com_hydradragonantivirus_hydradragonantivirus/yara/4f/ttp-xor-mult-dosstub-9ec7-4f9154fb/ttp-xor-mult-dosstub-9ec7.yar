rule TTP_XOR_MULT_DOSStub_9ec7 {
  strings:
    $key_9ec7 = { ca af [2] be b7 [2] f9 b5 [2] be a4 [2] f0 a8 [2] fc a2 [2] eb a9 [2] f0 e7 [2] cd }

  condition:
    any of them
}