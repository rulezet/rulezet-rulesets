rule TTP_XOR_MULT_DOSStub_8a1a {
  strings:
    $key_8a1a = { de 72 [2] aa 6a [2] ed 68 [2] aa 79 [2] e4 75 [2] e8 7f [2] ff 74 [2] e4 3a [2] d9 }

  condition:
    any of them
}