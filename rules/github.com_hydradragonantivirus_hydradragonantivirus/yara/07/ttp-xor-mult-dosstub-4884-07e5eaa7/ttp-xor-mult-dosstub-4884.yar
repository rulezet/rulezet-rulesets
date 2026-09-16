rule TTP_XOR_MULT_DOSStub_4884 {
  strings:
    $key_4884 = { 1c ec [2] 68 f4 [2] 2f f6 [2] 68 e7 [2] 26 eb [2] 2a e1 [2] 3d ea [2] 26 a4 [2] 1b }

  condition:
    any of them
}