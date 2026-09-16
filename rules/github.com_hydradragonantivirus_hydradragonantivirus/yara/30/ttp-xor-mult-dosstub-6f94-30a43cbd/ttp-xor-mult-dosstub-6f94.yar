rule TTP_XOR_MULT_DOSStub_6f94 {
  strings:
    $key_6f94 = { 3b fc [2] 4f e4 [2] 08 e6 [2] 4f f7 [2] 01 fb [2] 0d f1 [2] 1a fa [2] 01 b4 [2] 3c }

  condition:
    any of them
}