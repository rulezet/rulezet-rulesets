rule TTP_XOR_MULT_DOSStub_5391 {
  strings:
    $key_5391 = { 07 f9 [2] 73 e1 [2] 34 e3 [2] 73 f2 [2] 3d fe [2] 31 f4 [2] 26 ff [2] 3d b1 [2] 00 }

  condition:
    any of them
}