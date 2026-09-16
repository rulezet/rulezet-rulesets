rule TTP_XOR_MULT_DOSStub_8a72 {
  strings:
    $key_8a72 = { de 1a [2] aa 02 [2] ed 00 [2] aa 11 [2] e4 1d [2] e8 17 [2] ff 1c [2] e4 52 [2] d9 }

  condition:
    any of them
}