rule TTP_XOR_MULT_DOSStub_8edd {
  strings:
    $key_8edd = { da b5 [2] ae ad [2] e9 af [2] ae be [2] e0 b2 [2] ec b8 [2] fb b3 [2] e0 fd [2] dd }

  condition:
    any of them
}