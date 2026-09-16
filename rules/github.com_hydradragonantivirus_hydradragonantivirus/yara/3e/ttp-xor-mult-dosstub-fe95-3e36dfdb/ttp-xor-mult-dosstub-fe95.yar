rule TTP_XOR_MULT_DOSStub_fe95 {
  strings:
    $key_fe95 = { aa fd [2] de e5 [2] 99 e7 [2] de f6 [2] 90 fa [2] 9c f0 [2] 8b fb [2] 90 b5 [2] ad }

  condition:
    any of them
}