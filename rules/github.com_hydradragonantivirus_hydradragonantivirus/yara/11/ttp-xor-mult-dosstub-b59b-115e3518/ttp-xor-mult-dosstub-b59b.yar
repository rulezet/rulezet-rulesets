rule TTP_XOR_MULT_DOSStub_b59b {
  strings:
    $key_b59b = { e1 f3 [2] 95 eb [2] d2 e9 [2] 95 f8 [2] db f4 [2] d7 fe [2] c0 f5 [2] db bb [2] e6 }

  condition:
    any of them
}