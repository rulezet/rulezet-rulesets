rule TTP_XOR_MULT_DOSStub_b69a {
  strings:
    $key_b69a = { e2 f2 [2] 96 ea [2] d1 e8 [2] 96 f9 [2] d8 f5 [2] d4 ff [2] c3 f4 [2] d8 ba [2] e5 }

  condition:
    any of them
}