rule TTP_XOR_MULT_DOSStub_7294 {
  strings:
    $key_7294 = { 26 fc [2] 52 e4 [2] 15 e6 [2] 52 f7 [2] 1c fb [2] 10 f1 [2] 07 fa [2] 1c b4 [2] 21 }

  condition:
    any of them
}