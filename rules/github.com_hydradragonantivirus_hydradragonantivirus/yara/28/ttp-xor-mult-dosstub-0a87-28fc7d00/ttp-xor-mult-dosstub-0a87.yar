rule TTP_XOR_MULT_DOSStub_0a87 {
  strings:
    $key_0a87 = { 5e ef [2] 2a f7 [2] 6d f5 [2] 2a e4 [2] 64 e8 [2] 68 e2 [2] 7f e9 [2] 64 a7 [2] 59 }

  condition:
    any of them
}