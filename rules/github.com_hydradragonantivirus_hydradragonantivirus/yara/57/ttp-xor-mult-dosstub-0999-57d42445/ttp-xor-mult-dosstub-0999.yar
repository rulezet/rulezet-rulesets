rule TTP_XOR_MULT_DOSStub_0999 {
  strings:
    $key_0999 = { 5d f1 [2] 29 e9 [2] 6e eb [2] 29 fa [2] 67 f6 [2] 6b fc [2] 7c f7 [2] 67 b9 [2] 5a }

  condition:
    any of them
}