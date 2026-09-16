rule TTP_XOR_MULT_DOSStub_f0f9 {
  strings:
    $key_f0f9 = { a4 91 [2] d0 89 [2] 97 8b [2] d0 9a [2] 9e 96 [2] 92 9c [2] 85 97 [2] 9e d9 [2] a3 }

  condition:
    any of them
}