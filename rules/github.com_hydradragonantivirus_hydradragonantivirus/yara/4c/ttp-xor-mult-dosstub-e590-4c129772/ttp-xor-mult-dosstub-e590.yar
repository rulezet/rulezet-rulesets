rule TTP_XOR_MULT_DOSStub_e590 {
  strings:
    $key_e590 = { b1 f8 [2] c5 e0 [2] 82 e2 [2] c5 f3 [2] 8b ff [2] 87 f5 [2] 90 fe [2] 8b b0 [2] b6 }

  condition:
    any of them
}