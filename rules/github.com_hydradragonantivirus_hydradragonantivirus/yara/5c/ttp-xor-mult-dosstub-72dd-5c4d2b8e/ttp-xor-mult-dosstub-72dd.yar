rule TTP_XOR_MULT_DOSStub_72dd {
  strings:
    $key_72dd = { 26 b5 [2] 52 ad [2] 15 af [2] 52 be [2] 1c b2 [2] 10 b8 [2] 07 b3 [2] 1c fd [2] 21 }

  condition:
    any of them
}