rule TTP_XOR_MULT_DOSStub_0391 {
  strings:
    $key_0391 = { 57 f9 [2] 23 e1 [2] 64 e3 [2] 23 f2 [2] 6d fe [2] 61 f4 [2] 76 ff [2] 6d b1 [2] 50 }

  condition:
    any of them
}