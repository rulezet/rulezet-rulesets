rule TTP_XOR_MULT_DOSStub_3d96 {
  strings:
    $key_3d96 = { 69 fe [2] 1d e6 [2] 5a e4 [2] 1d f5 [2] 53 f9 [2] 5f f3 [2] 48 f8 [2] 53 b6 [2] 6e }

  condition:
    any of them
}