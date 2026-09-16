rule TTP_XOR_MULT_DOSStub_9ec4 {
  strings:
    $key_9ec4 = { ca ac [2] be b4 [2] f9 b6 [2] be a7 [2] f0 ab [2] fc a1 [2] eb aa [2] f0 e4 [2] cd }

  condition:
    any of them
}