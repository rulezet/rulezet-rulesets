rule TTP_XOR_MULT_DOSStub_01d9 {
  strings:
    $key_01d9 = { 55 b1 [2] 21 a9 [2] 66 ab [2] 21 ba [2] 6f b6 [2] 63 bc [2] 74 b7 [2] 6f f9 [2] 52 }

  condition:
    any of them
}