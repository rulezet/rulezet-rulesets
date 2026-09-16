rule TTP_XOR_MULT_DOSStub_0681 {
  strings:
    $key_0681 = { 52 e9 [2] 26 f1 [2] 61 f3 [2] 26 e2 [2] 68 ee [2] 64 e4 [2] 73 ef [2] 68 a1 [2] 55 }

  condition:
    any of them
}