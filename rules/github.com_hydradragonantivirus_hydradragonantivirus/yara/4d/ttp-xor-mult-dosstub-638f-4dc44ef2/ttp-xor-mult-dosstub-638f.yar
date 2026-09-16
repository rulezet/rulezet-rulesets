rule TTP_XOR_MULT_DOSStub_638f {
  strings:
    $key_638f = { 37 e7 [2] 43 ff [2] 04 fd [2] 43 ec [2] 0d e0 [2] 01 ea [2] 16 e1 [2] 0d af [2] 30 }

  condition:
    any of them
}