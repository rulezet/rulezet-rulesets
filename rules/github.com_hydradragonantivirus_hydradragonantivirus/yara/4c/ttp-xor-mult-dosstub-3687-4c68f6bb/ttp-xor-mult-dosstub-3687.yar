rule TTP_XOR_MULT_DOSStub_3687 {
  strings:
    $key_3687 = { 62 ef [2] 16 f7 [2] 51 f5 [2] 16 e4 [2] 58 e8 [2] 54 e2 [2] 43 e9 [2] 58 a7 [2] 65 }

  condition:
    any of them
}