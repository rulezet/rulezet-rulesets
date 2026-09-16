rule TTP_XOR_MULT_DOSStub_8a9d {
  strings:
    $key_8a9d = { de f5 [2] aa ed [2] ed ef [2] aa fe [2] e4 f2 [2] e8 f8 [2] ff f3 [2] e4 bd [2] d9 }

  condition:
    any of them
}