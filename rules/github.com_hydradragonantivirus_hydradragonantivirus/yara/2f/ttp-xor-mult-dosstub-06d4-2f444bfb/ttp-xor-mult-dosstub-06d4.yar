rule TTP_XOR_MULT_DOSStub_06d4 {
  strings:
    $key_06d4 = { 52 bc [2] 26 a4 [2] 61 a6 [2] 26 b7 [2] 68 bb [2] 64 b1 [2] 73 ba [2] 68 f4 [2] 55 }

  condition:
    any of them
}