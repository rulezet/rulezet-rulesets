rule TTP_XOR_MULT_DOSStub_4f8f {
  strings:
    $key_4f8f = { 1b e7 [2] 6f ff [2] 28 fd [2] 6f ec [2] 21 e0 [2] 2d ea [2] 3a e1 [2] 21 af [2] 1c }

  condition:
    any of them
}