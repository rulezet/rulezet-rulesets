rule TTP_XOR_MULT_DOSStub_2294 {
  strings:
    $key_2294 = { 76 fc [2] 02 e4 [2] 45 e6 [2] 02 f7 [2] 4c fb [2] 40 f1 [2] 57 fa [2] 4c b4 [2] 71 }

  condition:
    any of them
}