rule TTP_XOR_MULT_DOSStub_9ec5 {
  strings:
    $key_9ec5 = { ca ad [2] be b5 [2] f9 b7 [2] be a6 [2] f0 aa [2] fc a0 [2] eb ab [2] f0 e5 [2] cd }

  condition:
    any of them
}