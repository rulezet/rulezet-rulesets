rule TTP_XOR_MULT_DOSStub_1999 {
  strings:
    $key_1999 = { 4d f1 [2] 39 e9 [2] 7e eb [2] 39 fa [2] 77 f6 [2] 7b fc [2] 6c f7 [2] 77 b9 [2] 4a }

  condition:
    any of them
}