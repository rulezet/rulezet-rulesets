rule TTP_XOR_MULT_DOSStub_7e93 {
  strings:
    $key_7e93 = { 2a fb [2] 5e e3 [2] 19 e1 [2] 5e f0 [2] 10 fc [2] 1c f6 [2] 0b fd [2] 10 b3 [2] 2d }

  condition:
    any of them
}