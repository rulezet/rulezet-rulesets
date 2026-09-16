rule TTP_XOR_MULT_DOSStub_ee94 {
  strings:
    $key_ee94 = { ba fc [2] ce e4 [2] 89 e6 [2] ce f7 [2] 80 fb [2] 8c f1 [2] 9b fa [2] 80 b4 [2] bd }

  condition:
    any of them
}