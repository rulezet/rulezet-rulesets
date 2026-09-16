rule TTP_XOR_MULT_DOSStub_5294 {
  strings:
    $key_5294 = { 06 fc [2] 72 e4 [2] 35 e6 [2] 72 f7 [2] 3c fb [2] 30 f1 [2] 27 fa [2] 3c b4 [2] 01 }

  condition:
    any of them
}