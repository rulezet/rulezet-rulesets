rule TTP_XOR_MULT_DOSStub_6780 {
  strings:
    $key_6780 = { 33 e8 [2] 47 f0 [2] 00 f2 [2] 47 e3 [2] 09 ef [2] 05 e5 [2] 12 ee [2] 09 a0 [2] 34 }

  condition:
    any of them
}