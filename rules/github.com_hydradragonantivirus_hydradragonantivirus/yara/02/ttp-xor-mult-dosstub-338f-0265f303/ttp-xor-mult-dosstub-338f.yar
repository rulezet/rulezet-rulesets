rule TTP_XOR_MULT_DOSStub_338f {
  strings:
    $key_338f = { 67 e7 [2] 13 ff [2] 54 fd [2] 13 ec [2] 5d e0 [2] 51 ea [2] 46 e1 [2] 5d af [2] 60 }

  condition:
    any of them
}