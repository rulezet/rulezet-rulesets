rule TTP_XOR_MULT_DOSStub_8a3a {
  strings:
    $key_8a3a = { de 52 [2] aa 4a [2] ed 48 [2] aa 59 [2] e4 55 [2] e8 5f [2] ff 54 [2] e4 1a [2] d9 }

  condition:
    any of them
}