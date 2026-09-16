rule TTP_XOR_MULT_DOSStub_2f8f {
  strings:
    $key_2f8f = { 7b e7 [2] 0f ff [2] 48 fd [2] 0f ec [2] 41 e0 [2] 4d ea [2] 5a e1 [2] 41 af [2] 7c }

  condition:
    any of them
}