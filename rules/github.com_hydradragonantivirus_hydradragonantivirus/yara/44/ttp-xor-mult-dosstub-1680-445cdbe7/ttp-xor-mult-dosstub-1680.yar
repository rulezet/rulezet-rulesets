rule TTP_XOR_MULT_DOSStub_1680 {
  strings:
    $key_1680 = { 42 e8 [2] 36 f0 [2] 71 f2 [2] 36 e3 [2] 78 ef [2] 74 e5 [2] 63 ee [2] 78 a0 [2] 45 }

  condition:
    any of them
}