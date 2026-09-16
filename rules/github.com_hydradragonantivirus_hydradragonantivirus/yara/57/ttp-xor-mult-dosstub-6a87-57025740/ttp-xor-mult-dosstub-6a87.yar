rule TTP_XOR_MULT_DOSStub_6a87 {
  strings:
    $key_6a87 = { 3e ef [2] 4a f7 [2] 0d f5 [2] 4a e4 [2] 04 e8 [2] 08 e2 [2] 1f e9 [2] 04 a7 [2] 39 }

  condition:
    any of them
}