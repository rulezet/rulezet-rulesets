rule TTP_XOR_MULT_DOSStub_f590 {
  strings:
    $key_f590 = { a1 f8 [2] d5 e0 [2] 92 e2 [2] d5 f3 [2] 9b ff [2] 97 f5 [2] 80 fe [2] 9b b0 [2] a6 }

  condition:
    any of them
}