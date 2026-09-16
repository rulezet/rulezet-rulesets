rule TTP_XOR_MULT_DOSStub_8a2a {
  strings:
    $key_8a2a = { de 42 [2] aa 5a [2] ed 58 [2] aa 49 [2] e4 45 [2] e8 4f [2] ff 44 [2] e4 0a [2] d9 }

  condition:
    any of them
}