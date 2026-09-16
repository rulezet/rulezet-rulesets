rule TTP_XOR_MULT_DOSStub_9ec3 {
  strings:
    $key_9ec3 = { ca ab [2] be b3 [2] f9 b1 [2] be a0 [2] f0 ac [2] fc a6 [2] eb ad [2] f0 e3 [2] cd }

  condition:
    any of them
}