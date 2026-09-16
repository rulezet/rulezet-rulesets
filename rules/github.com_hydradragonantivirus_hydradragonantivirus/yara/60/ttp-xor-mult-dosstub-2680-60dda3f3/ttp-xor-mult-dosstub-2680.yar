rule TTP_XOR_MULT_DOSStub_2680 {
  strings:
    $key_2680 = { 72 e8 [2] 06 f0 [2] 41 f2 [2] 06 e3 [2] 48 ef [2] 44 e5 [2] 53 ee [2] 48 a0 [2] 75 }

  condition:
    any of them
}