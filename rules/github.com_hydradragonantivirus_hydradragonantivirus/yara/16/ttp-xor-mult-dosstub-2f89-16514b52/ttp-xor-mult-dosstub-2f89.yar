rule TTP_XOR_MULT_DOSStub_2f89 {
  strings:
    $key_2f89 = { 7b e1 [2] 0f f9 [2] 48 fb [2] 0f ea [2] 41 e6 [2] 4d ec [2] 5a e7 [2] 41 a9 [2] 7c }

  condition:
    any of them
}