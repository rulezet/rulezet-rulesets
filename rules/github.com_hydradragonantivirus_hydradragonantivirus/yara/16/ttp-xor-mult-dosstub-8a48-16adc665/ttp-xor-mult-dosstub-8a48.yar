rule TTP_XOR_MULT_DOSStub_8a48 {
  strings:
    $key_8a48 = { de 20 [2] aa 38 [2] ed 3a [2] aa 2b [2] e4 27 [2] e8 2d [2] ff 26 [2] e4 68 [2] d9 }

  condition:
    any of them
}