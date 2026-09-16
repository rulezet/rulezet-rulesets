rule TTP_XOR_MULT_DOSStub_3f89 {
  strings:
    $key_3f89 = { 6b e1 [2] 1f f9 [2] 58 fb [2] 1f ea [2] 51 e6 [2] 5d ec [2] 4a e7 [2] 51 a9 [2] 6c }

  condition:
    any of them
}