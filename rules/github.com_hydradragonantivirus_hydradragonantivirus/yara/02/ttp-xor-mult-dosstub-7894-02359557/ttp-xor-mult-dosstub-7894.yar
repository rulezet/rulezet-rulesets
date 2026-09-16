rule TTP_XOR_MULT_DOSStub_7894 {
  strings:
    $key_7894 = { 2c fc [2] 58 e4 [2] 1f e6 [2] 58 f7 [2] 16 fb [2] 1a f1 [2] 0d fa [2] 16 b4 [2] 2b }

  condition:
    any of them
}