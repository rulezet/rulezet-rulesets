rule TTP_XOR_MULT_DOSStub_8a70 {
  strings:
    $key_8a70 = { de 18 [2] aa 00 [2] ed 02 [2] aa 13 [2] e4 1f [2] e8 15 [2] ff 1e [2] e4 50 [2] d9 }

  condition:
    any of them
}