rule TTP_XOR_MULT_DOSStub_57dd {
  strings:
    $key_57dd = { 03 b5 [2] 77 ad [2] 30 af [2] 77 be [2] 39 b2 [2] 35 b8 [2] 22 b3 [2] 39 fd [2] 04 }

  condition:
    any of them
}