rule TTP_XOR_MULT_DOSStub_0f8f {
  strings:
    $key_0f8f = { 5b e7 [2] 2f ff [2] 68 fd [2] 2f ec [2] 61 e0 [2] 6d ea [2] 7a e1 [2] 61 af [2] 5c }

  condition:
    any of them
}