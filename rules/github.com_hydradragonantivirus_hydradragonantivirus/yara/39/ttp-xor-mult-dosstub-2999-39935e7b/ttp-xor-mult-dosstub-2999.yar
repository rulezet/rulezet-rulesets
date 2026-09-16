rule TTP_XOR_MULT_DOSStub_2999 {
  strings:
    $key_2999 = { 7d f1 [2] 09 e9 [2] 4e eb [2] 09 fa [2] 47 f6 [2] 4b fc [2] 5c f7 [2] 47 b9 [2] 7a }

  condition:
    any of them
}