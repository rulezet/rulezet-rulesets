rule TTP_XOR_MULT_DOSStub_9edf {
  strings:
    $key_9edf = { ca b7 [2] be af [2] f9 ad [2] be bc [2] f0 b0 [2] fc ba [2] eb b1 [2] f0 ff [2] cd }

  condition:
    any of them
}