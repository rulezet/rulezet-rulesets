rule TTP_XOR_MULT_DOSStub_8a47 {
  strings:
    $key_8a47 = { de 2f [2] aa 37 [2] ed 35 [2] aa 24 [2] e4 28 [2] e8 22 [2] ff 29 [2] e4 67 [2] d9 }

  condition:
    any of them
}