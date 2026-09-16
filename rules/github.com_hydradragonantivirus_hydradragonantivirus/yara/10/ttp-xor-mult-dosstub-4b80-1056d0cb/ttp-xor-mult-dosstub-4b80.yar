rule TTP_XOR_MULT_DOSStub_4b80 {
  strings:
    $key_4b80 = { 1f e8 [2] 6b f0 [2] 2c f2 [2] 6b e3 [2] 25 ef [2] 29 e5 [2] 3e ee [2] 25 a0 [2] 18 }

  condition:
    any of them
}