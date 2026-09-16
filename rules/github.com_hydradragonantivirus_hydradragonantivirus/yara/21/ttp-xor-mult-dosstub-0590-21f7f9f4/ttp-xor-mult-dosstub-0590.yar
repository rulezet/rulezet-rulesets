rule TTP_XOR_MULT_DOSStub_0590 {
  strings:
    $key_0590 = { 51 f8 [2] 25 e0 [2] 62 e2 [2] 25 f3 [2] 6b ff [2] 67 f5 [2] 70 fe [2] 6b b0 [2] 56 }

  condition:
    any of them
}