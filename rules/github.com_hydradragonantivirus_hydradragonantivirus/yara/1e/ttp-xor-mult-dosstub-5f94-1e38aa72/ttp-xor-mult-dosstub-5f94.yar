rule TTP_XOR_MULT_DOSStub_5f94 {
  strings:
    $key_5f94 = { 0b fc [2] 7f e4 [2] 38 e6 [2] 7f f7 [2] 31 fb [2] 3d f1 [2] 2a fa [2] 31 b4 [2] 0c }

  condition:
    any of them
}