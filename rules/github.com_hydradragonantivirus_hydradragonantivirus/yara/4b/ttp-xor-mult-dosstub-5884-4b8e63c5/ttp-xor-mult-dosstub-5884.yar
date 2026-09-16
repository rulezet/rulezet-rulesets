rule TTP_XOR_MULT_DOSStub_5884 {
  strings:
    $key_5884 = { 0c ec [2] 78 f4 [2] 3f f6 [2] 78 e7 [2] 36 eb [2] 3a e1 [2] 2d ea [2] 36 a4 [2] 0b }

  condition:
    any of them
}