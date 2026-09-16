rule TTP_XOR_MULT_DOSStub_e7d0 {
  strings:
    $key_e7d0 = { b3 b8 [2] c7 a0 [2] 80 a2 [2] c7 b3 [2] 89 bf [2] 85 b5 [2] 92 be [2] 89 f0 [2] b4 }

  condition:
    any of them
}