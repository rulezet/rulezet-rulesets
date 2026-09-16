rule TTP_XOR_MULT_DOSStub_678f {
  strings:
    $key_678f = { 33 e7 [2] 47 ff [2] 00 fd [2] 47 ec [2] 09 e0 [2] 05 ea [2] 12 e1 [2] 09 af [2] 34 }

  condition:
    any of them
}