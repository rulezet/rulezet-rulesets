rule TTP_XOR_MULT_DOSStub_53d9 {
  strings:
    $key_53d9 = { 07 b1 [2] 73 a9 [2] 34 ab [2] 73 ba [2] 3d b6 [2] 31 bc [2] 26 b7 [2] 3d f9 [2] 00 }

  condition:
    any of them
}