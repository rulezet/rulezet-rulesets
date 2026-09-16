rule TTP_XOR_MULT_DOSStub_46d4 {
  strings:
    $key_46d4 = { 12 bc [2] 66 a4 [2] 21 a6 [2] 66 b7 [2] 28 bb [2] 24 b1 [2] 33 ba [2] 28 f4 [2] 15 }

  condition:
    any of them
}