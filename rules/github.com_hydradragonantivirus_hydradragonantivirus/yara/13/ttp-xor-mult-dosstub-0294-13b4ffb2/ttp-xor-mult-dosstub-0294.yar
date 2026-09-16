rule TTP_XOR_MULT_DOSStub_0294 {
  strings:
    $key_0294 = { 56 fc [2] 22 e4 [2] 65 e6 [2] 22 f7 [2] 6c fb [2] 60 f1 [2] 77 fa [2] 6c b4 [2] 51 }

  condition:
    any of them
}