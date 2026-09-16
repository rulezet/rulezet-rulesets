rule TTP_XOR_MULT_DOSStub_53c3 {
  strings:
    $key_53c3 = { 07 ab [2] 73 b3 [2] 34 b1 [2] 73 a0 [2] 3d ac [2] 31 a6 [2] 26 ad [2] 3d e3 [2] 00 }

  condition:
    any of them
}