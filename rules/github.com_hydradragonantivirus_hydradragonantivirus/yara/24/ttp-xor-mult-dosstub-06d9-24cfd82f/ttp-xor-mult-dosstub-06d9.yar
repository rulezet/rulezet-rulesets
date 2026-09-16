rule TTP_XOR_MULT_DOSStub_06d9 {
  strings:
    $key_06d9 = { 52 b1 [2] 26 a9 [2] 61 ab [2] 26 ba [2] 68 b6 [2] 64 bc [2] 73 b7 [2] 68 f9 [2] 55 }

  condition:
    any of them
}