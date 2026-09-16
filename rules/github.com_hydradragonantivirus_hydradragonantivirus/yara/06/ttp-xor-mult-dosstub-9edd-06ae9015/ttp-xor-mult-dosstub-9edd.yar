rule TTP_XOR_MULT_DOSStub_9edd {
  strings:
    $key_9edd = { ca b5 [2] be ad [2] f9 af [2] be be [2] f0 b2 [2] fc b8 [2] eb b3 [2] f0 fd [2] cd }

  condition:
    any of them
}