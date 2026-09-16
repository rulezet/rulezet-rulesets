rule TTP_XOR_MULT_DOSStub_9ecc {
  strings:
    $key_9ecc = { ca a4 [2] be bc [2] f9 be [2] be af [2] f0 a3 [2] fc a9 [2] eb a2 [2] f0 ec [2] cd }

  condition:
    any of them
}