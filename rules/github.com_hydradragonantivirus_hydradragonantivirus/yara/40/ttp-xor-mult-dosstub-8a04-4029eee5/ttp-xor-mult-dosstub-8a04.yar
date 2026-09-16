rule TTP_XOR_MULT_DOSStub_8a04 {
  strings:
    $key_8a04 = { de 6c [2] aa 74 [2] ed 76 [2] aa 67 [2] e4 6b [2] e8 61 [2] ff 6a [2] e4 24 [2] d9 }

  condition:
    any of them
}