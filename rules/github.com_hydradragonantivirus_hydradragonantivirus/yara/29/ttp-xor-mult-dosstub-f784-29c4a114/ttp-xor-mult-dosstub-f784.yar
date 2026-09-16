rule TTP_XOR_MULT_DOSStub_f784 {
  strings:
    $key_f784 = { a3 ec [2] d7 f4 [2] 90 f6 [2] d7 e7 [2] 99 eb [2] 95 e1 [2] 82 ea [2] 99 a4 [2] a4 }

  condition:
    any of them
}