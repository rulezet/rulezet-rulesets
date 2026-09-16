rule TTP_XOR_MULT_DOSStub_fe94 {
  strings:
    $key_fe94 = { aa fc [2] de e4 [2] 99 e6 [2] de f7 [2] 90 fb [2] 9c f1 [2] 8b fa [2] 90 b4 [2] ad }

  condition:
    any of them
}