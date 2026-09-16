rule TTP_XOR_MULT_DOSStub_b084 {
  strings:
    $key_b084 = { e4 ec [2] 90 f4 [2] d7 f6 [2] 90 e7 [2] de eb [2] d2 e1 [2] c5 ea [2] de a4 [2] e3 }

  condition:
    any of them
}