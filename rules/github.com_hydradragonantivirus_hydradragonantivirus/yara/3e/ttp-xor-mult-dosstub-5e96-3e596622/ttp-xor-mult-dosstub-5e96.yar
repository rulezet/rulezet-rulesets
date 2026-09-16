rule TTP_XOR_MULT_DOSStub_5e96 {
  strings:
    $key_5e96 = { 0a fe [2] 7e e6 [2] 39 e4 [2] 7e f5 [2] 30 f9 [2] 3c f3 [2] 2b f8 [2] 30 b6 [2] 0d }

  condition:
    any of them
}