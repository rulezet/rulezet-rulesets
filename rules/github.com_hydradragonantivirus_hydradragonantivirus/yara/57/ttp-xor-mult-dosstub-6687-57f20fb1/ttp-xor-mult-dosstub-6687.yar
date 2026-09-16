rule TTP_XOR_MULT_DOSStub_6687 {
  strings:
    $key_6687 = { 32 ef [2] 46 f7 [2] 01 f5 [2] 46 e4 [2] 08 e8 [2] 04 e2 [2] 13 e9 [2] 08 a7 [2] 35 }

  condition:
    any of them
}