rule TTP_XOR_MULT_DOSStub_2d90 {
  strings:
    $key_2d90 = { 79 f8 [2] 0d e0 [2] 4a e2 [2] 0d f3 [2] 43 ff [2] 4f f5 [2] 58 fe [2] 43 b0 [2] 7e }

  condition:
    any of them
}