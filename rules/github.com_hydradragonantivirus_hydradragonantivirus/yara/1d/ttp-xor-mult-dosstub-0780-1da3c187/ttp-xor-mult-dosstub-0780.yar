rule TTP_XOR_MULT_DOSStub_0780 {
  strings:
    $key_0780 = { 53 e8 [2] 27 f0 [2] 60 f2 [2] 27 e3 [2] 69 ef [2] 65 e5 [2] 72 ee [2] 69 a0 [2] 54 }

  condition:
    any of them
}