rule TTP_XOR_MULT_DOSStub_8a49 {
  strings:
    $key_8a49 = { de 21 [2] aa 39 [2] ed 3b [2] aa 2a [2] e4 26 [2] e8 2c [2] ff 27 [2] e4 69 [2] d9 }

  condition:
    any of them
}