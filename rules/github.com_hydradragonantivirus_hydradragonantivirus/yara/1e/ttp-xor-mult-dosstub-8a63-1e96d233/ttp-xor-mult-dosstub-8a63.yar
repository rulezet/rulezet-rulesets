rule TTP_XOR_MULT_DOSStub_8a63 {
  strings:
    $key_8a63 = { de 0b [2] aa 13 [2] ed 11 [2] aa 00 [2] e4 0c [2] e8 06 [2] ff 0d [2] e4 43 [2] d9 }

  condition:
    any of them
}