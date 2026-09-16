rule TTP_XOR_MULT_DOSStub_9ec2 {
  strings:
    $key_9ec2 = { ca aa [2] be b2 [2] f9 b0 [2] be a1 [2] f0 ad [2] fc a7 [2] eb ac [2] f0 e2 [2] cd }

  condition:
    any of them
}