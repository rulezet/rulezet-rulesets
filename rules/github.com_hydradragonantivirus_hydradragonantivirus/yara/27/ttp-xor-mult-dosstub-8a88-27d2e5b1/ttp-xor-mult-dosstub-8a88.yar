rule TTP_XOR_MULT_DOSStub_8a88 {
  strings:
    $key_8a88 = { de e0 [2] aa f8 [2] ed fa [2] aa eb [2] e4 e7 [2] e8 ed [2] ff e6 [2] e4 a8 [2] d9 }

  condition:
    any of them
}