rule TTP_XOR_MULT_DOSStub_408f {
  strings:
    $key_408f = { 14 e7 [2] 60 ff [2] 27 fd [2] 60 ec [2] 2e e0 [2] 22 ea [2] 35 e1 [2] 2e af [2] 13 }

  condition:
    any of them
}