rule TTP_XOR_MULT_DOSStub_3391 {
  strings:
    $key_3391 = { 67 f9 [2] 13 e1 [2] 54 e3 [2] 13 f2 [2] 5d fe [2] 51 f4 [2] 46 ff [2] 5d b1 [2] 60 }

  condition:
    any of them
}