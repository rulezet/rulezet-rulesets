rule TTP_XOR_MULT_DOSStub_8a4a {
  strings:
    $key_8a4a = { de 22 [2] aa 3a [2] ed 38 [2] aa 29 [2] e4 25 [2] e8 2f [2] ff 24 [2] e4 6a [2] d9 }

  condition:
    any of them
}