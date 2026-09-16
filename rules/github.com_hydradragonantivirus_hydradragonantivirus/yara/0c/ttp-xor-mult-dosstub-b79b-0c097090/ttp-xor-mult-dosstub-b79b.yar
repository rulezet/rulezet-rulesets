rule TTP_XOR_MULT_DOSStub_b79b {
  strings:
    $key_b79b = { e3 f3 [2] 97 eb [2] d0 e9 [2] 97 f8 [2] d9 f4 [2] d5 fe [2] c2 f5 [2] d9 bb [2] e4 }

  condition:
    any of them
}