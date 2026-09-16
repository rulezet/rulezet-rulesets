rule TTP_XOR_MULT_DOSStub_8a22 {
  strings:
    $key_8a22 = { de 4a [2] aa 52 [2] ed 50 [2] aa 41 [2] e4 4d [2] e8 47 [2] ff 4c [2] e4 02 [2] d9 }

  condition:
    any of them
}