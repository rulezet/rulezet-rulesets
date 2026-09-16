rule TTP_XOR_MULT_DOSStub_53c6 {
  strings:
    $key_53c6 = { 07 ae [2] 73 b6 [2] 34 b4 [2] 73 a5 [2] 3d a9 [2] 31 a3 [2] 26 a8 [2] 3d e6 [2] 00 }

  condition:
    any of them
}