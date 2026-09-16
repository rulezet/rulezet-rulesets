rule TTP_XOR_MULT_DOSStub_b790 {
  strings:
    $key_b790 = { e3 f8 [2] 97 e0 [2] d0 e2 [2] 97 f3 [2] d9 ff [2] d5 f5 [2] c2 fe [2] d9 b0 [2] e4 }

  condition:
    any of them
}