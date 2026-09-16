rule TTP_XOR_MULT_DOSStub_3f8f {
  strings:
    $key_3f8f = { 6b e7 [2] 1f ff [2] 58 fd [2] 1f ec [2] 51 e0 [2] 5d ea [2] 4a e1 [2] 51 af [2] 6c }

  condition:
    any of them
}