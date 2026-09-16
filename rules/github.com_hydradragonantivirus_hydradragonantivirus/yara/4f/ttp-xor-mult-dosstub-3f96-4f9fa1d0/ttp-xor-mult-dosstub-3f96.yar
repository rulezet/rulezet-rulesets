rule TTP_XOR_MULT_DOSStub_3f96 {
  strings:
    $key_3f96 = { 6b fe [2] 1f e6 [2] 58 e4 [2] 1f f5 [2] 51 f9 [2] 5d f3 [2] 4a f8 [2] 51 b6 [2] 6c }

  condition:
    any of them
}