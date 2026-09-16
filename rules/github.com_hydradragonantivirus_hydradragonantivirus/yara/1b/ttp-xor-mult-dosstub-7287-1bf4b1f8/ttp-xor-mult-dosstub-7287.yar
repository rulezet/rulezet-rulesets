rule TTP_XOR_MULT_DOSStub_7287 {
  strings:
    $key_7287 = { 26 ef [2] 52 f7 [2] 15 f5 [2] 52 e4 [2] 1c e8 [2] 10 e2 [2] 07 e9 [2] 1c a7 [2] 21 }

  condition:
    any of them
}