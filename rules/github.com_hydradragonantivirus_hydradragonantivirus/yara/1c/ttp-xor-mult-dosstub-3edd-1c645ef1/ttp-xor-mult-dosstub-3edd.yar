rule TTP_XOR_MULT_DOSStub_3edd {
  strings:
    $key_3edd = { 6a b5 [2] 1e ad [2] 59 af [2] 1e be [2] 50 b2 [2] 5c b8 [2] 4b b3 [2] 50 fd [2] 6d }

  condition:
    any of them
}