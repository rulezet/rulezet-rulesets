rule TTP_XOR_MULT_DOSStub_8a5a {
  strings:
    $key_8a5a = { de 32 [2] aa 2a [2] ed 28 [2] aa 39 [2] e4 35 [2] e8 3f [2] ff 34 [2] e4 7a [2] d9 }

  condition:
    any of them
}