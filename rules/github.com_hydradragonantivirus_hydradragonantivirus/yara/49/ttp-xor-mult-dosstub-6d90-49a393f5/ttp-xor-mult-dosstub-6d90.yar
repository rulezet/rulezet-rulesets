rule TTP_XOR_MULT_DOSStub_6d90 {
  strings:
    $key_6d90 = { 39 f8 [2] 4d e0 [2] 0a e2 [2] 4d f3 [2] 03 ff [2] 0f f5 [2] 18 fe [2] 03 b0 [2] 3e }

  condition:
    any of them
}