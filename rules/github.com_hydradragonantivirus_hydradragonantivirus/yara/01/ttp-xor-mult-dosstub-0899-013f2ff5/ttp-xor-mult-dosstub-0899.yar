rule TTP_XOR_MULT_DOSStub_0899 {
  strings:
    $key_0899 = { 5c f1 [2] 28 e9 [2] 6f eb [2] 28 fa [2] 66 f6 [2] 6a fc [2] 7d f7 [2] 66 b9 [2] 5b }

  condition:
    any of them
}