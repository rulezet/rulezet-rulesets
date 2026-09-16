rule TTP_XOR_MULT_DOSStub_0d90 {
  strings:
    $key_0d90 = { 59 f8 [2] 2d e0 [2] 6a e2 [2] 2d f3 [2] 63 ff [2] 6f f5 [2] 78 fe [2] 63 b0 [2] 5e }

  condition:
    any of them
}