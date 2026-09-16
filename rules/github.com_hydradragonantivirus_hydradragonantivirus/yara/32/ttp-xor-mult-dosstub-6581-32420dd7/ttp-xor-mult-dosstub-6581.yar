rule TTP_XOR_MULT_DOSStub_6581 {
  strings:
    $key_6581 = { 31 e9 [2] 45 f1 [2] 02 f3 [2] 45 e2 [2] 0b ee [2] 07 e4 [2] 10 ef [2] 0b a1 [2] 36 }

  condition:
    any of them
}