rule TTP_XOR_MULT_DOSStub_76d9 {
  strings:
    $key_76d9 = { 22 b1 [2] 56 a9 [2] 11 ab [2] 56 ba [2] 18 b6 [2] 14 bc [2] 03 b7 [2] 18 f9 [2] 25 }

  condition:
    any of them
}