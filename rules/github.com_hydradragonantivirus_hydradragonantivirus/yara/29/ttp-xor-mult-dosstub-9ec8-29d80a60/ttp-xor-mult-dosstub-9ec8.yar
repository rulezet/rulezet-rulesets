rule TTP_XOR_MULT_DOSStub_9ec8 {
  strings:
    $key_9ec8 = { ca a0 [2] be b8 [2] f9 ba [2] be ab [2] f0 a7 [2] fc ad [2] eb a6 [2] f0 e8 [2] cd }

  condition:
    any of them
}