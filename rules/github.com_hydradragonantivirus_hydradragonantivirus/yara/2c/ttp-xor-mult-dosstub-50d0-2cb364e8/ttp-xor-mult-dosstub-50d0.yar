rule TTP_XOR_MULT_DOSStub_50d0 {
  strings:
    $key_50d0 = { 04 b8 [2] 70 a0 [2] 37 a2 [2] 70 b3 [2] 3e bf [2] 32 b5 [2] 25 be [2] 3e f0 [2] 03 }

  condition:
    any of them
}