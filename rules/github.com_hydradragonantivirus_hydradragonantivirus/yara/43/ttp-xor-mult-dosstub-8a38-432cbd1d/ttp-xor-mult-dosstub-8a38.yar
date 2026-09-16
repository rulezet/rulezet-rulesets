rule TTP_XOR_MULT_DOSStub_8a38 {
  strings:
    $key_8a38 = { de 50 [2] aa 48 [2] ed 4a [2] aa 5b [2] e4 57 [2] e8 5d [2] ff 56 [2] e4 18 [2] d9 }

  condition:
    any of them
}