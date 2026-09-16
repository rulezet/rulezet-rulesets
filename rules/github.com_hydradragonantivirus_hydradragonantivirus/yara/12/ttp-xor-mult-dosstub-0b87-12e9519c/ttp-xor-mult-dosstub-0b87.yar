rule TTP_XOR_MULT_DOSStub_0b87 {
  strings:
    $key_0b87 = { 5f ef [2] 2b f7 [2] 6c f5 [2] 2b e4 [2] 65 e8 [2] 69 e2 [2] 7e e9 [2] 65 a7 [2] 58 }

  condition:
    any of them
}