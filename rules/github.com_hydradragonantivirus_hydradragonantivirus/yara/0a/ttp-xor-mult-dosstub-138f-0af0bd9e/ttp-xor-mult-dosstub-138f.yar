rule TTP_XOR_MULT_DOSStub_138f {
  strings:
    $key_138f = { 47 e7 [2] 33 ff [2] 74 fd [2] 33 ec [2] 7d e0 [2] 71 ea [2] 66 e1 [2] 7d af [2] 40 }

  condition:
    any of them
}