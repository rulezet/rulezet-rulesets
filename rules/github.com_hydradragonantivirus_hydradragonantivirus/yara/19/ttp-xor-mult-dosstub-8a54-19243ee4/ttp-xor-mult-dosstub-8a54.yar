rule TTP_XOR_MULT_DOSStub_8a54 {
  strings:
    $key_8a54 = { de 3c [2] aa 24 [2] ed 26 [2] aa 37 [2] e4 3b [2] e8 31 [2] ff 3a [2] e4 74 [2] d9 }

  condition:
    any of them
}