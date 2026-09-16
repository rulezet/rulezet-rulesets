rule TTP_XOR_MULT_DOSStub_1687 {
  strings:
    $key_1687 = { 42 ef [2] 36 f7 [2] 71 f5 [2] 36 e4 [2] 78 e8 [2] 74 e2 [2] 63 e9 [2] 78 a7 [2] 45 }

  condition:
    any of them
}