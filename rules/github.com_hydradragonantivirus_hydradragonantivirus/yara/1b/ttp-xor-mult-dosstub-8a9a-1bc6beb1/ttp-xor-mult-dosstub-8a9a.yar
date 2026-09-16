rule TTP_XOR_MULT_DOSStub_8a9a {
  strings:
    $key_8a9a = { de f2 [2] aa ea [2] ed e8 [2] aa f9 [2] e4 f5 [2] e8 ff [2] ff f4 [2] e4 ba [2] d9 }

  condition:
    any of them
}