rule TTP_XOR_MULT_DOSStub_8a12 {
  strings:
    $key_8a12 = { de 7a [2] aa 62 [2] ed 60 [2] aa 71 [2] e4 7d [2] e8 77 [2] ff 7c [2] e4 32 [2] d9 }

  condition:
    any of them
}