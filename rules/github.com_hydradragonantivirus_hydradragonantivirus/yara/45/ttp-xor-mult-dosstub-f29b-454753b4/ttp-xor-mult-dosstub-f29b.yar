rule TTP_XOR_MULT_DOSStub_f29b {
  strings:
    $key_f29b = { a6 f3 [2] d2 eb [2] 95 e9 [2] d2 f8 [2] 9c f4 [2] 90 fe [2] 87 f5 [2] 9c bb [2] a1 }

  condition:
    any of them
}