rule TTP_XOR_MULT_DOSStub_8a36 {
  strings:
    $key_8a36 = { de 5e [2] aa 46 [2] ed 44 [2] aa 55 [2] e4 59 [2] e8 53 [2] ff 58 [2] e4 16 [2] d9 }

  condition:
    any of them
}