rule TTP_XOR_MULT_DOSStub_8a05 {
  strings:
    $key_8a05 = { de 6d [2] aa 75 [2] ed 77 [2] aa 66 [2] e4 6a [2] e8 60 [2] ff 6b [2] e4 25 [2] d9 }

  condition:
    any of them
}