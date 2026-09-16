rule TTP_XOR_MULT_DOSStub_528f {
  strings:
    $key_528f = { 06 e7 [2] 72 ff [2] 35 fd [2] 72 ec [2] 3c e0 [2] 30 ea [2] 27 e1 [2] 3c af [2] 01 }

  condition:
    any of them
}