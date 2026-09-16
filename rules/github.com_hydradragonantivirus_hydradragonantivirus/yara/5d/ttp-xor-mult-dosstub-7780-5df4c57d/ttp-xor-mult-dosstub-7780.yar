rule TTP_XOR_MULT_DOSStub_7780 {
  strings:
    $key_7780 = { 23 e8 [2] 57 f0 [2] 10 f2 [2] 57 e3 [2] 19 ef [2] 15 e5 [2] 02 ee [2] 19 a0 [2] 24 }

  condition:
    any of them
}