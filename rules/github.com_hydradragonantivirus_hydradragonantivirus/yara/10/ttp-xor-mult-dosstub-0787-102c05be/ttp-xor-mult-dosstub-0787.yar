rule TTP_XOR_MULT_DOSStub_0787 {
  strings:
    $key_0787 = { 53 ef [2] 27 f7 [2] 60 f5 [2] 27 e4 [2] 69 e8 [2] 65 e2 [2] 72 e9 [2] 69 a7 [2] 54 }

  condition:
    any of them
}