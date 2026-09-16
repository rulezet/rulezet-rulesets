rule TTP_XOR_MULT_DOSStub_5b96 {
  strings:
    $key_5b96 = { 0f fe [2] 7b e6 [2] 3c e4 [2] 7b f5 [2] 35 f9 [2] 39 f3 [2] 2e f8 [2] 35 b6 [2] 08 }

  condition:
    any of them
}