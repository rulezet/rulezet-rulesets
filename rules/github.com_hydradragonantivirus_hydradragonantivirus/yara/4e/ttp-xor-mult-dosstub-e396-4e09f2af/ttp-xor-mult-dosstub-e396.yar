rule TTP_XOR_MULT_DOSStub_e396 {
  strings:
    $key_e396 = { b7 fe [2] c3 e6 [2] 84 e4 [2] c3 f5 [2] 8d f9 [2] 81 f3 [2] 96 f8 [2] 8d b6 [2] b0 }

  condition:
    any of them
}