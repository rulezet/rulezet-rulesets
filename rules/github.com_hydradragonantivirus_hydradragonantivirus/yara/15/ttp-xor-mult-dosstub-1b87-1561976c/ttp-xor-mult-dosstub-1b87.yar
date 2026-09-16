rule TTP_XOR_MULT_DOSStub_1b87 {
  strings:
    $key_1b87 = { 4f ef [2] 3b f7 [2] 7c f5 [2] 3b e4 [2] 75 e8 [2] 79 e2 [2] 6e e9 [2] 75 a7 [2] 48 }

  condition:
    any of them
}