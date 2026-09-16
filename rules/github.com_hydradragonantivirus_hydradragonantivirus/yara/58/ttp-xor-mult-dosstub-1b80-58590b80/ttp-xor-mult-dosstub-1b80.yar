rule TTP_XOR_MULT_DOSStub_1b80 {
  strings:
    $key_1b80 = { 4f e8 [2] 3b f0 [2] 7c f2 [2] 3b e3 [2] 75 ef [2] 79 e5 [2] 6e ee [2] 75 a0 [2] 48 }

  condition:
    any of them
}