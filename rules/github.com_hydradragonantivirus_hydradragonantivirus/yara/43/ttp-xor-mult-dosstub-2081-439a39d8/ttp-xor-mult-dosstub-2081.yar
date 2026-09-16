rule TTP_XOR_MULT_DOSStub_2081 {
  strings:
    $key_2081 = { 74 e9 [2] 00 f1 [2] 47 f3 [2] 00 e2 [2] 4e ee [2] 42 e4 [2] 55 ef [2] 4e a1 [2] 73 }

  condition:
    any of them
}