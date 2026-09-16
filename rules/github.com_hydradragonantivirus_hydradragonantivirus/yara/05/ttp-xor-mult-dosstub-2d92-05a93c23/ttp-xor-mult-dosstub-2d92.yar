rule TTP_XOR_MULT_DOSStub_2d92 {
  strings:
    $key_2d92 = { 79 fa [2] 0d e2 [2] 4a e0 [2] 0d f1 [2] 43 fd [2] 4f f7 [2] 58 fc [2] 43 b2 [2] 7e }

  condition:
    any of them
}