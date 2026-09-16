rule TTP_XOR_MULT_DOSStub_5687 {
  strings:
    $key_5687 = { 02 ef [2] 76 f7 [2] 31 f5 [2] 76 e4 [2] 38 e8 [2] 34 e2 [2] 23 e9 [2] 38 a7 [2] 05 }

  condition:
    any of them
}