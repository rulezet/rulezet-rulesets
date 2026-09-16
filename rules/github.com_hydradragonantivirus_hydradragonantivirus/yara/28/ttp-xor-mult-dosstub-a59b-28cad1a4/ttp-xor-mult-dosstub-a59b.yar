rule TTP_XOR_MULT_DOSStub_a59b {
  strings:
    $key_a59b = { f1 f3 [2] 85 eb [2] c2 e9 [2] 85 f8 [2] cb f4 [2] c7 fe [2] d0 f5 [2] cb bb [2] f6 }

  condition:
    any of them
}