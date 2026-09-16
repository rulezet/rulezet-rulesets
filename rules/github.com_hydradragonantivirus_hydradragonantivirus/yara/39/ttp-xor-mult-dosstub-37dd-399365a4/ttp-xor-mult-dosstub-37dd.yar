rule TTP_XOR_MULT_DOSStub_37dd {
  strings:
    $key_37dd = { 63 b5 [2] 17 ad [2] 50 af [2] 17 be [2] 59 b2 [2] 55 b8 [2] 42 b3 [2] 59 fd [2] 64 }

  condition:
    any of them
}