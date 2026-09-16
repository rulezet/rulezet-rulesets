rule TTP_XOR_MULT_DOSStub_4f89 {
  strings:
    $key_4f89 = { 1b e1 [2] 6f f9 [2] 28 fb [2] 6f ea [2] 21 e6 [2] 2d ec [2] 3a e7 [2] 21 a9 [2] 1c }

  condition:
    any of them
}