rule TTP_XOR_MULT_DOSStub_b296 {
  strings:
    $key_b296 = { e6 fe [2] 92 e6 [2] d5 e4 [2] 92 f5 [2] dc f9 [2] d0 f3 [2] c7 f8 [2] dc b6 [2] e1 }

  condition:
    any of them
}