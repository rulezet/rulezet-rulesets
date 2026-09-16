rule TTP_XOR_MULT_DOSStub_36d9 {
  strings:
    $key_36d9 = { 62 b1 [2] 16 a9 [2] 51 ab [2] 16 ba [2] 58 b6 [2] 54 bc [2] 43 b7 [2] 58 f9 [2] 65 }

  condition:
    any of them
}