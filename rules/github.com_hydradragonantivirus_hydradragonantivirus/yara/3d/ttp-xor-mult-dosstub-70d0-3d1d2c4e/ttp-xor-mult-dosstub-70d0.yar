rule TTP_XOR_MULT_DOSStub_70d0 {
  strings:
    $key_70d0 = { 24 b8 [2] 50 a0 [2] 17 a2 [2] 50 b3 [2] 1e bf [2] 12 b5 [2] 05 be [2] 1e f0 [2] 23 }

  condition:
    any of them
}