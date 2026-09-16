rule TTP_XOR_MULT_DOSStub_3087 {
  strings:
    $key_3087 = { 64 ef [2] 10 f7 [2] 57 f5 [2] 10 e4 [2] 5e e8 [2] 52 e2 [2] 45 e9 [2] 5e a7 [2] 63 }

  condition:
    any of them
}