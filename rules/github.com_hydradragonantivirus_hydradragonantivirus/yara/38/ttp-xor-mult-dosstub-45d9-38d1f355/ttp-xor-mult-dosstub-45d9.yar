rule TTP_XOR_MULT_DOSStub_45d9 {
  strings:
    $key_45d9 = { 11 b1 [2] 65 a9 [2] 22 ab [2] 65 ba [2] 2b b6 [2] 27 bc [2] 30 b7 [2] 2b f9 [2] 16 }

  condition:
    any of them
}