rule TTP_XOR_MULT_DOSStub_1f8f {
  strings:
    $key_1f8f = { 4b e7 [2] 3f ff [2] 78 fd [2] 3f ec [2] 71 e0 [2] 7d ea [2] 6a e1 [2] 71 af [2] 4c }

  condition:
    any of them
}