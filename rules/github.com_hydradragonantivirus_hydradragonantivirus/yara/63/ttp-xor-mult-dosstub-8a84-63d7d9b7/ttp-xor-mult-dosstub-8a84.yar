rule TTP_XOR_MULT_DOSStub_8a84 {
  strings:
    $key_8a84 = { de ec [2] aa f4 [2] ed f6 [2] aa e7 [2] e4 eb [2] e8 e1 [2] ff ea [2] e4 a4 [2] d9 }

  condition:
    any of them
}