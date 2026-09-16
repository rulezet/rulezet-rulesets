rule TTP_XOR_MULT_DOSStub_53d6 {
  strings:
    $key_53d6 = { 07 be [2] 73 a6 [2] 34 a4 [2] 73 b5 [2] 3d b9 [2] 31 b3 [2] 26 b8 [2] 3d f6 [2] 00 }

  condition:
    any of them
}