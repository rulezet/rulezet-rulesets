rule TTP_XOR_MULT_DOSStub_00d9 {
  strings:
    $key_00d9 = { 54 b1 [2] 20 a9 [2] 67 ab [2] 20 ba [2] 6e b6 [2] 62 bc [2] 75 b7 [2] 6e f9 [2] 53 }

  condition:
    any of them
}