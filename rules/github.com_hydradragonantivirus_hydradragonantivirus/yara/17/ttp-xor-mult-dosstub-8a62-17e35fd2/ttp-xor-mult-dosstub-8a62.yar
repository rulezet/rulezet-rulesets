rule TTP_XOR_MULT_DOSStub_8a62 {
  strings:
    $key_8a62 = { de 0a [2] aa 12 [2] ed 10 [2] aa 01 [2] e4 0d [2] e8 07 [2] ff 0c [2] e4 42 [2] d9 }

  condition:
    any of them
}