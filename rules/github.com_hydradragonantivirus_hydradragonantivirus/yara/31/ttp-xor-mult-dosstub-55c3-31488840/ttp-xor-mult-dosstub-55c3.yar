rule TTP_XOR_MULT_DOSStub_55c3 {
  strings:
    $key_55c3 = { 01 ab [2] 75 b3 [2] 32 b1 [2] 75 a0 [2] 3b ac [2] 37 a6 [2] 20 ad [2] 3b e3 [2] 06 }

  condition:
    any of them
}