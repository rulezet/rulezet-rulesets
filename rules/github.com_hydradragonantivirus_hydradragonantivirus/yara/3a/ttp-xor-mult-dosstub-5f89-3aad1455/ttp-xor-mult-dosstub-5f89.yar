rule TTP_XOR_MULT_DOSStub_5f89 {
  strings:
    $key_5f89 = { 0b e1 [2] 7f f9 [2] 38 fb [2] 7f ea [2] 31 e6 [2] 3d ec [2] 2a e7 [2] 31 a9 [2] 0c }

  condition:
    any of them
}