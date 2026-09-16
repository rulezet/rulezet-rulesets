rule TTP_XOR_MULT_DOSStub_7e8f {
  strings:
    $key_7e8f = { 2a e7 [2] 5e ff [2] 19 fd [2] 5e ec [2] 10 e0 [2] 1c ea [2] 0b e1 [2] 10 af [2] 2d }

  condition:
    any of them
}