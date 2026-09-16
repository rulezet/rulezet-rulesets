rule TTP_XOR_MULT_DOSStub_7e96 {
  strings:
    $key_7e96 = { 2a fe [2] 5e e6 [2] 19 e4 [2] 5e f5 [2] 10 f9 [2] 1c f3 [2] 0b f8 [2] 10 b6 [2] 2d }

  condition:
    any of them
}