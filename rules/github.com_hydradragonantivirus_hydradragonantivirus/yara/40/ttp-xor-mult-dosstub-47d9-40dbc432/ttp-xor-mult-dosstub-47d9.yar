rule TTP_XOR_MULT_DOSStub_47d9 {
  strings:
    $key_47d9 = { 13 b1 [2] 67 a9 [2] 20 ab [2] 67 ba [2] 29 b6 [2] 25 bc [2] 32 b7 [2] 29 f9 [2] 14 }

  condition:
    any of them
}