rule TTP_XOR_MULT_DOSStub_7996 {
  strings:
    $key_7996 = { 2d fe [2] 59 e6 [2] 1e e4 [2] 59 f5 [2] 17 f9 [2] 1b f3 [2] 0c f8 [2] 17 b6 [2] 2a }

  condition:
    any of them
}