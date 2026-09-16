rule TTP_XOR_MULT_DOSStub_2987 {
  strings:
    $key_2987 = { 7d ef [2] 09 f7 [2] 4e f5 [2] 09 e4 [2] 47 e8 [2] 4b e2 [2] 5c e9 [2] 47 a7 [2] 7a }

  condition:
    any of them
}