rule TTP_XOR_MULT_DOSStub_5081 {
  strings:
    $key_5081 = { 04 e9 [2] 70 f1 [2] 37 f3 [2] 70 e2 [2] 3e ee [2] 32 e4 [2] 25 ef [2] 3e a1 [2] 03 }

  condition:
    any of them
}