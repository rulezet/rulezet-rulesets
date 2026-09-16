rule TTP_XOR_MULT_DOSStub_05c8 {
  strings:
    $key_05c8 = { 51 a0 [2] 25 b8 [2] 62 ba [2] 25 ab [2] 6b a7 [2] 67 ad [2] 70 a6 [2] 6b e8 [2] 56 }

  condition:
    any of them
}