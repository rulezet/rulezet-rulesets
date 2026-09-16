rule TTP_XOR_MULT_DOSStub_fe93 {
  strings:
    $key_fe93 = { aa fb [2] de e3 [2] 99 e1 [2] de f0 [2] 90 fc [2] 9c f6 [2] 8b fd [2] 90 b3 [2] ad }

  condition:
    any of them
}