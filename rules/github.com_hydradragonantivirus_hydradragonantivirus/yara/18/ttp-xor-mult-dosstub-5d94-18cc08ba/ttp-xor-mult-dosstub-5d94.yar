rule TTP_XOR_MULT_DOSStub_5d94 {
  strings:
    $key_5d94 = { 09 fc [2] 7d e4 [2] 3a e6 [2] 7d f7 [2] 33 fb [2] 3f f1 [2] 28 fa [2] 33 b4 [2] 0e }

  condition:
    any of them
}