rule TTP_XOR_MULT_DOSStub_6d96 {
  strings:
    $key_6d96 = { 39 fe [2] 4d e6 [2] 0a e4 [2] 4d f5 [2] 03 f9 [2] 0f f3 [2] 18 f8 [2] 03 b6 [2] 3e }

  condition:
    any of them
}