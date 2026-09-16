rule TTP_XOR_MULT_DOSStub_8a44 {
  strings:
    $key_8a44 = { de 2c [2] aa 34 [2] ed 36 [2] aa 27 [2] e4 2b [2] e8 21 [2] ff 2a [2] e4 64 [2] d9 }

  condition:
    any of them
}