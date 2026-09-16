rule TTP_XOR_MULT_DOSStub_2787 {
  strings:
    $key_2787 = { 73 ef [2] 07 f7 [2] 40 f5 [2] 07 e4 [2] 49 e8 [2] 45 e2 [2] 52 e9 [2] 49 a7 [2] 74 }

  condition:
    any of them
}