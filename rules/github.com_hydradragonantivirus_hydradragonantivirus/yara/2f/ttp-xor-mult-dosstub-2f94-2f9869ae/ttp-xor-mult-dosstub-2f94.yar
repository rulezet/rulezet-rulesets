rule TTP_XOR_MULT_DOSStub_2f94 {
  strings:
    $key_2f94 = { 7b fc [2] 0f e4 [2] 48 e6 [2] 0f f7 [2] 41 fb [2] 4d f1 [2] 5a fa [2] 41 b4 [2] 7c }

  condition:
    any of them
}