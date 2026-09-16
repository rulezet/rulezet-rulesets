rule TTP_XOR_MULT_DOSStub_578f {
  strings:
    $key_578f = { 03 e7 [2] 77 ff [2] 30 fd [2] 77 ec [2] 39 e0 [2] 35 ea [2] 22 e1 [2] 39 af [2] 04 }

  condition:
    any of them
}