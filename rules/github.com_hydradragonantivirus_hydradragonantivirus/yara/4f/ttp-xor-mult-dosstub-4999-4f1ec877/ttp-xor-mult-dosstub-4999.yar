rule TTP_XOR_MULT_DOSStub_4999 {
  strings:
    $key_4999 = { 1d f1 [2] 69 e9 [2] 2e eb [2] 69 fa [2] 27 f6 [2] 2b fc [2] 3c f7 [2] 27 b9 [2] 1a }

  condition:
    any of them
}