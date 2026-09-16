rule TTP_XOR_MULT_DOSStub_b184 {
  strings:
    $key_b184 = { e5 ec [2] 91 f4 [2] d6 f6 [2] 91 e7 [2] df eb [2] d3 e1 [2] c4 ea [2] df a4 [2] e2 }

  condition:
    any of them
}