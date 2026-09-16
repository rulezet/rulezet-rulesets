rule TTP_XOR_MULT_DOSStub_4d90 {
  strings:
    $key_4d90 = { 19 f8 [2] 6d e0 [2] 2a e2 [2] 6d f3 [2] 23 ff [2] 2f f5 [2] 38 fe [2] 23 b0 [2] 1e }

  condition:
    any of them
}