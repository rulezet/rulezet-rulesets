rule TTP_XOR_MULT_DOSStub_65c3 {
  strings:
    $key_65c3 = { 31 ab [2] 45 b3 [2] 02 b1 [2] 45 a0 [2] 0b ac [2] 07 a6 [2] 10 ad [2] 0b e3 [2] 36 }

  condition:
    any of them
}