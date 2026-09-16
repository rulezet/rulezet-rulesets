rule TTP_XOR_MULT_DOSStub_7edd {
  strings:
    $key_7edd = { 2a b5 [2] 5e ad [2] 19 af [2] 5e be [2] 10 b2 [2] 1c b8 [2] 0b b3 [2] 10 fd [2] 2d }

  condition:
    any of them
}