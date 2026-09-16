rule TTP_XOR_MULT_DOSStub_4a94 {
  strings:
    $key_4a94 = { 1e fc [2] 6a e4 [2] 2d e6 [2] 6a f7 [2] 24 fb [2] 28 f1 [2] 3f fa [2] 24 b4 [2] 19 }

  condition:
    any of them
}