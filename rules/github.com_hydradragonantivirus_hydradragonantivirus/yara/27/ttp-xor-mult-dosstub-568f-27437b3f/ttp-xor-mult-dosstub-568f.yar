rule TTP_XOR_MULT_DOSStub_568f {
  strings:
    $key_568f = { 02 e7 [2] 76 ff [2] 31 fd [2] 76 ec [2] 38 e0 [2] 34 ea [2] 23 e1 [2] 38 af [2] 05 }

  condition:
    any of them
}