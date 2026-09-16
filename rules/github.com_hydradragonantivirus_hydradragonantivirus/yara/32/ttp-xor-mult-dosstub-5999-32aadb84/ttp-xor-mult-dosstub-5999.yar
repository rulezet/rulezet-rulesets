rule TTP_XOR_MULT_DOSStub_5999 {
  strings:
    $key_5999 = { 0d f1 [2] 79 e9 [2] 3e eb [2] 79 fa [2] 37 f6 [2] 3b fc [2] 2c f7 [2] 37 b9 [2] 0a }

  condition:
    any of them
}