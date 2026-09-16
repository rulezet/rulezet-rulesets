rule TTP_XOR_MULT_DOSStub_9ec6 {
  strings:
    $key_9ec6 = { ca ae [2] be b6 [2] f9 b4 [2] be a5 [2] f0 a9 [2] fc a3 [2] eb a8 [2] f0 e6 [2] cd }

  condition:
    any of them
}