rule TTP_XOR_MULT_DOSStub_0e8f {
  strings:
    $key_0e8f = { 5a e7 [2] 2e ff [2] 69 fd [2] 2e ec [2] 60 e0 [2] 6c ea [2] 7b e1 [2] 60 af [2] 5d }

  condition:
    any of them
}