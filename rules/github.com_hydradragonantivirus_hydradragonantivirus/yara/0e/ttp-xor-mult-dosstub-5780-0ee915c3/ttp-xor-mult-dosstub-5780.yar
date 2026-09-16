rule TTP_XOR_MULT_DOSStub_5780 {
  strings:
    $key_5780 = { 03 e8 [2] 77 f0 [2] 30 f2 [2] 77 e3 [2] 39 ef [2] 35 e5 [2] 22 ee [2] 39 a0 [2] 04 }

  condition:
    any of them
}