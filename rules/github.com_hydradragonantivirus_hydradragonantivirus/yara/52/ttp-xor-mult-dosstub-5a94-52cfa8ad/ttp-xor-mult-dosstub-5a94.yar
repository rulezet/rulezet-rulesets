rule TTP_XOR_MULT_DOSStub_5a94 {
  strings:
    $key_5a94 = { 0e fc [2] 7a e4 [2] 3d e6 [2] 7a f7 [2] 34 fb [2] 38 f1 [2] 2f fa [2] 34 b4 [2] 09 }

  condition:
    any of them
}