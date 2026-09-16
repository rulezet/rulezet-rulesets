rule TTP_XOR_MULT_DOSStub_a184 {
  strings:
    $key_a184 = { f5 ec [2] 81 f4 [2] c6 f6 [2] 81 e7 [2] cf eb [2] c3 e1 [2] d4 ea [2] cf a4 [2] f2 }

  condition:
    any of them
}