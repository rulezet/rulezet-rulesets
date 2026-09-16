rule TTP_XOR_MULT_DOSStub_53c8 {
  strings:
    $key_53c8 = { 07 a0 [2] 73 b8 [2] 34 ba [2] 73 ab [2] 3d a7 [2] 31 ad [2] 26 a6 [2] 3d e8 [2] 00 }

  condition:
    any of them
}