rule TTP_XOR_MULT_DOSStub_8a08 {
  strings:
    $key_8a08 = { de 60 [2] aa 78 [2] ed 7a [2] aa 6b [2] e4 67 [2] e8 6d [2] ff 66 [2] e4 28 [2] d9 }

  condition:
    any of them
}