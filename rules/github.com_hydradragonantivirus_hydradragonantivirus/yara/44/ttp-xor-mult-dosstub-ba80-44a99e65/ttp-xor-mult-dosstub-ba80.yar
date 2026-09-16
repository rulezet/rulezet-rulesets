rule TTP_XOR_MULT_DOSStub_ba80 {
  strings:
    $key_ba80 = { ee e8 [2] 9a f0 [2] dd f2 [2] 9a e3 [2] d4 ef [2] d8 e5 [2] cf ee [2] d4 a0 [2] e9 }

  condition:
    any of them
}