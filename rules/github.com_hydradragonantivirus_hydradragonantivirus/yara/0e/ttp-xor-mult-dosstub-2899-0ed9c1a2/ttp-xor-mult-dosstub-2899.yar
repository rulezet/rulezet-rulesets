rule TTP_XOR_MULT_DOSStub_2899 {
  strings:
    $key_2899 = { 7c f1 [2] 08 e9 [2] 4f eb [2] 08 fa [2] 46 f6 [2] 4a fc [2] 5d f7 [2] 46 b9 [2] 7b }

  condition:
    any of them
}