rule TTP_XOR_MULT_DOSStub_10d9 {
  strings:
    $key_10d9 = { 44 b1 [2] 30 a9 [2] 77 ab [2] 30 ba [2] 7e b6 [2] 72 bc [2] 65 b7 [2] 7e f9 [2] 43 }

  condition:
    any of them
}