rule TTP_XOR_MULT_DOSStub_8a8e {
  strings:
    $key_8a8e = { de e6 [2] aa fe [2] ed fc [2] aa ed [2] e4 e1 [2] e8 eb [2] ff e0 [2] e4 ae [2] d9 }

  condition:
    any of them
}