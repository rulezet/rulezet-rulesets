rule TTP_XOR_MULT_DOSStub_53db {
  strings:
    $key_53db = { 07 b3 [2] 73 ab [2] 34 a9 [2] 73 b8 [2] 3d b4 [2] 31 be [2] 26 b5 [2] 3d fb [2] 00 }

  condition:
    any of them
}