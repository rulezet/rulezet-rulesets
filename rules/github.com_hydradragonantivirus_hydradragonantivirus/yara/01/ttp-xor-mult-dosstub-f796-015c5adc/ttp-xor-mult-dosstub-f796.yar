rule TTP_XOR_MULT_DOSStub_f796 {
  strings:
    $key_f796 = { a3 fe [2] d7 e6 [2] 90 e4 [2] d7 f5 [2] 99 f9 [2] 95 f3 [2] 82 f8 [2] 99 b6 [2] a4 }

  condition:
    any of them
}