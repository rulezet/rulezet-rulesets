rule TTP_XOR_MULT_DOSStub_1f96 {
  strings:
    $key_1f96 = { 4b fe [2] 3f e6 [2] 78 e4 [2] 3f f5 [2] 71 f9 [2] 7d f3 [2] 6a f8 [2] 71 b6 [2] 4c }

  condition:
    any of them
}