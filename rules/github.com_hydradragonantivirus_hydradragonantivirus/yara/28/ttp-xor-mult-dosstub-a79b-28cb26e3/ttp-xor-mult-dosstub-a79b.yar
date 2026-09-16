rule TTP_XOR_MULT_DOSStub_a79b {
  strings:
    $key_a79b = { f3 f3 [2] 87 eb [2] c0 e9 [2] 87 f8 [2] c9 f4 [2] c5 fe [2] d2 f5 [2] c9 bb [2] f4 }

  condition:
    any of them
}