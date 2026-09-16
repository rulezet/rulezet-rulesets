rule TTP_XOR_MULT_DOSStub_8af2 {
  strings:
    $key_8af2 = { de 9a [2] aa 82 [2] ed 80 [2] aa 91 [2] e4 9d [2] e8 97 [2] ff 9c [2] e4 d2 [2] d9 }

  condition:
    any of them
}