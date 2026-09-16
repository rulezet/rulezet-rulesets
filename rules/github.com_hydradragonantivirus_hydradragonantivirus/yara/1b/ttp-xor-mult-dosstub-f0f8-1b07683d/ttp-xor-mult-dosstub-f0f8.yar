rule TTP_XOR_MULT_DOSStub_f0f8 {
  strings:
    $key_f0f8 = { a4 90 [2] d0 88 [2] 97 8a [2] d0 9b [2] 9e 97 [2] 92 9d [2] 85 96 [2] 9e d8 [2] a3 }

  condition:
    any of them
}