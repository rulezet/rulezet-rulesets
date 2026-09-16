rule TTP_XOR_MULT_DOSStub_8a45 {
  strings:
    $key_8a45 = { de 2d [2] aa 35 [2] ed 37 [2] aa 26 [2] e4 2a [2] e8 20 [2] ff 2b [2] e4 65 [2] d9 }

  condition:
    any of them
}