rule TTP_XOR_MULT_DOSStub_9ec1 {
  strings:
    $key_9ec1 = { ca a9 [2] be b1 [2] f9 b3 [2] be a2 [2] f0 ae [2] fc a4 [2] eb af [2] f0 e1 [2] cd }

  condition:
    any of them
}