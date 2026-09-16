rule TTP_XOR_MULT_DOSStub_d9dd {
  strings:
    $key_d9dd = { 8d b5 [2] f9 ad [2] be af [2] f9 be [2] b7 b2 [2] bb b8 [2] ac b3 [2] b7 fd [2] 8a }

  condition:
    any of them
}