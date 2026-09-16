rule TTP_XOR_MULT_DOSStub_6b87 {
  strings:
    $key_6b87 = { 3f ef [2] 4b f7 [2] 0c f5 [2] 4b e4 [2] 05 e8 [2] 09 e2 [2] 1e e9 [2] 05 a7 [2] 38 }

  condition:
    any of them
}