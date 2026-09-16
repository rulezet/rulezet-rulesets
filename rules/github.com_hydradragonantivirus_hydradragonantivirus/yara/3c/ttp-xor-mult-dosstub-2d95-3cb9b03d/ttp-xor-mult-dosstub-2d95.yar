rule TTP_XOR_MULT_DOSStub_2d95 {
  strings:
    $key_2d95 = { 79 fd [2] 0d e5 [2] 4a e7 [2] 0d f6 [2] 43 fa [2] 4f f0 [2] 58 fb [2] 43 b5 [2] 7e }

  condition:
    any of them
}