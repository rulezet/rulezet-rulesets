rule TTP_XOR_MULT_DOSStub_30d0 {
  strings:
    $key_30d0 = { 64 b8 [2] 10 a0 [2] 57 a2 [2] 10 b3 [2] 5e bf [2] 52 b5 [2] 45 be [2] 5e f0 [2] 63 }

  condition:
    any of them
}