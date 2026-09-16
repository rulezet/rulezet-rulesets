rule TTP_XOR_MULT_DOSStub_8af4 {
  strings:
    $key_8af4 = { de 9c [2] aa 84 [2] ed 86 [2] aa 97 [2] e4 9b [2] e8 91 [2] ff 9a [2] e4 d4 [2] d9 }

  condition:
    any of them
}