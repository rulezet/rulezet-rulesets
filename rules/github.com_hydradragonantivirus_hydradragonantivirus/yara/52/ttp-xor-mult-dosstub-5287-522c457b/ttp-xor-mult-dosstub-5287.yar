rule TTP_XOR_MULT_DOSStub_5287 {
  strings:
    $key_5287 = { 06 ef [2] 72 f7 [2] 35 f5 [2] 72 e4 [2] 3c e8 [2] 30 e2 [2] 27 e9 [2] 3c a7 [2] 01 }

  condition:
    any of them
}