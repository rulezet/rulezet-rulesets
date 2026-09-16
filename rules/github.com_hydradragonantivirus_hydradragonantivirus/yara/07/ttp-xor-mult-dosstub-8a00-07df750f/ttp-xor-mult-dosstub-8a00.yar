rule TTP_XOR_MULT_DOSStub_8a00 {
  strings:
    $key_8a00 = { de 68 [2] aa 70 [2] ed 72 [2] aa 63 [2] e4 6f [2] e8 65 [2] ff 6e [2] e4 20 [2] d9 }

  condition:
    any of them
}