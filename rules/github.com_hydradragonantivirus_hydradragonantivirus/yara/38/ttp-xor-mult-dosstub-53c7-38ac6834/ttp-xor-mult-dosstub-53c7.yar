rule TTP_XOR_MULT_DOSStub_53c7 {
  strings:
    $key_53c7 = { 07 af [2] 73 b7 [2] 34 b5 [2] 73 a4 [2] 3d a8 [2] 31 a2 [2] 26 a9 [2] 3d e7 [2] 00 }

  condition:
    any of them
}