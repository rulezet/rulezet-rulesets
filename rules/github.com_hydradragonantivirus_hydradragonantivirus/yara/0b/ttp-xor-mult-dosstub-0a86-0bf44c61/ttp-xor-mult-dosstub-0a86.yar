rule TTP_XOR_MULT_DOSStub_0a86 {
  strings:
    $key_0a86 = { 5e ee [2] 2a f6 [2] 6d f4 [2] 2a e5 [2] 64 e9 [2] 68 e3 [2] 7f e8 [2] 64 a6 [2] 59 }

  condition:
    any of them
}