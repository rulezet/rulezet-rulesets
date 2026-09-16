rule TTP_XOR_MULT_DOSStub_e2dd {
  strings:
    $key_e2dd = { b6 b5 [2] c2 ad [2] 85 af [2] c2 be [2] 8c b2 [2] 80 b8 [2] 97 b3 [2] 8c fd [2] b1 }

  condition:
    any of them
}