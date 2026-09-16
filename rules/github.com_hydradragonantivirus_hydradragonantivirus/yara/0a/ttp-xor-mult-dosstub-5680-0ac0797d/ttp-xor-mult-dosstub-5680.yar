rule TTP_XOR_MULT_DOSStub_5680 {
  strings:
    $key_5680 = { 02 e8 [2] 76 f0 [2] 31 f2 [2] 76 e3 [2] 38 ef [2] 34 e5 [2] 23 ee [2] 38 a0 [2] 05 }

  condition:
    any of them
}