rule TTP_XOR_MULT_DOSStub_53d1 {
  strings:
    $key_53d1 = { 07 b9 [2] 73 a1 [2] 34 a3 [2] 73 b2 [2] 3d be [2] 31 b4 [2] 26 bf [2] 3d f1 [2] 00 }

  condition:
    any of them
}