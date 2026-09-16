rule TTP_XOR_MULT_DOSStub_68dd {
  strings:
    $key_68dd = { 3c b5 [2] 48 ad [2] 0f af [2] 48 be [2] 06 b2 [2] 0a b8 [2] 1d b3 [2] 06 fd [2] 3b }

  condition:
    any of them
}