rule TTP_XOR_MULT_DOSStub_058f {
  strings:
    $key_058f = { 51 e7 [2] 25 ff [2] 62 fd [2] 25 ec [2] 6b e0 [2] 67 ea [2] 70 e1 [2] 6b af [2] 56 }

  condition:
    any of them
}