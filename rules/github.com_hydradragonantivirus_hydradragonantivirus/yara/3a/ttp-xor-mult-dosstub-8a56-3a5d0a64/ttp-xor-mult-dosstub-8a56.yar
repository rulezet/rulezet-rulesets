rule TTP_XOR_MULT_DOSStub_8a56 {
  strings:
    $key_8a56 = { de 3e [2] aa 26 [2] ed 24 [2] aa 35 [2] e4 39 [2] e8 33 [2] ff 38 [2] e4 76 [2] d9 }

  condition:
    any of them
}