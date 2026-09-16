rule TTP_XOR_MULT_DOSStub_48dd {
  strings:
    $key_48dd = { 1c b5 [2] 68 ad [2] 2f af [2] 68 be [2] 26 b2 [2] 2a b8 [2] 3d b3 [2] 26 fd [2] 1b }

  condition:
    any of them
}