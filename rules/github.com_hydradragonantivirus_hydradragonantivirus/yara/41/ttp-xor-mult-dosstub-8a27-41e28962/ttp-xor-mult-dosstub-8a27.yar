rule TTP_XOR_MULT_DOSStub_8a27 {
  strings:
    $key_8a27 = { de 4f [2] aa 57 [2] ed 55 [2] aa 44 [2] e4 48 [2] e8 42 [2] ff 49 [2] e4 07 [2] d9 }

  condition:
    any of them
}