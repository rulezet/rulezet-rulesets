rule TTP_XOR_MULT_DOSStub_1b96 {
  strings:
    $key_1b96 = { 4f fe [2] 3b e6 [2] 7c e4 [2] 3b f5 [2] 75 f9 [2] 79 f3 [2] 6e f8 [2] 75 b6 [2] 48 }

  condition:
    any of them
}