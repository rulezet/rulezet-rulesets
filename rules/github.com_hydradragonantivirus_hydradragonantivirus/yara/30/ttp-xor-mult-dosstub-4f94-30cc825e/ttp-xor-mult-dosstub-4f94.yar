rule TTP_XOR_MULT_DOSStub_4f94 {
  strings:
    $key_4f94 = { 1b fc [2] 6f e4 [2] 28 e6 [2] 6f f7 [2] 21 fb [2] 2d f1 [2] 3a fa [2] 21 b4 [2] 1c }

  condition:
    any of them
}