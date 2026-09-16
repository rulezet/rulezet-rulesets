rule TTP_XOR_MULT_DOSStub_0f89 {
  strings:
    $key_0f89 = { 5b e1 [2] 2f f9 [2] 68 fb [2] 2f ea [2] 61 e6 [2] 6d ec [2] 7a e7 [2] 61 a9 [2] 5c }

  condition:
    any of them
}