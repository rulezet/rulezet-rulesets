rule TTP_XOR_MULT_DOSStub_5edd {
  strings:
    $key_5edd = { 0a b5 [2] 7e ad [2] 39 af [2] 7e be [2] 30 b2 [2] 3c b8 [2] 2b b3 [2] 30 fd [2] 0d }

  condition:
    any of them
}