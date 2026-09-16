rule TTP_XOR_MULT_DOSStub_8a79 {
  strings:
    $key_8a79 = { de 11 [2] aa 09 [2] ed 0b [2] aa 1a [2] e4 16 [2] e8 1c [2] ff 17 [2] e4 59 [2] d9 }

  condition:
    any of them
}