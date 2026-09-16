rule TTP_XOR_MULT_DOSStub_8af1 {
  strings:
    $key_8af1 = { de 99 [2] aa 81 [2] ed 83 [2] aa 92 [2] e4 9e [2] e8 94 [2] ff 9f [2] e4 d1 [2] d9 }

  condition:
    any of them
}