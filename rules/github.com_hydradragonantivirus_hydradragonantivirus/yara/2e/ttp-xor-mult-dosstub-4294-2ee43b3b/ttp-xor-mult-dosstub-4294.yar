rule TTP_XOR_MULT_DOSStub_4294 {
  strings:
    $key_4294 = { 16 fc [2] 62 e4 [2] 25 e6 [2] 62 f7 [2] 2c fb [2] 20 f1 [2] 37 fa [2] 2c b4 [2] 11 }

  condition:
    any of them
}