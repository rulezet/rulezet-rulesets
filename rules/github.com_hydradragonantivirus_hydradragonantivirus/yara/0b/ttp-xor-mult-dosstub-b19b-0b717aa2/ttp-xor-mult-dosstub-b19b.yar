rule TTP_XOR_MULT_DOSStub_b19b {
  strings:
    $key_b19b = { e5 f3 [2] 91 eb [2] d6 e9 [2] 91 f8 [2] df f4 [2] d3 fe [2] c4 f5 [2] df bb [2] e2 }

  condition:
    any of them
}