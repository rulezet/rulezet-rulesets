rule TTP_XOR_MULT_DOSStub_8a02 {
  strings:
    $key_8a02 = { de 6a [2] aa 72 [2] ed 70 [2] aa 61 [2] e4 6d [2] e8 67 [2] ff 6c [2] e4 22 [2] d9 }

  condition:
    any of them
}