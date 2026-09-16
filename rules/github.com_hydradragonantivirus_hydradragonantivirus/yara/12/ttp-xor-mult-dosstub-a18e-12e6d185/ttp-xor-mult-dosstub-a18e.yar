rule TTP_XOR_MULT_DOSStub_a18e {
  strings:
    $key_a18e = { f5 e6 [2] 81 fe [2] c6 fc [2] 81 ed [2] cf e1 [2] c3 eb [2] d4 e0 [2] cf ae [2] f2 }

  condition:
    any of them
}