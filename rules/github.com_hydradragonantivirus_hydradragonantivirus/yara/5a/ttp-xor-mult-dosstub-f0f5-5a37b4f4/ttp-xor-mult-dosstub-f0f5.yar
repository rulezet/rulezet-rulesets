rule TTP_XOR_MULT_DOSStub_f0f5 {
  strings:
    $key_f0f5 = { a4 9d [2] d0 85 [2] 97 87 [2] d0 96 [2] 9e 9a [2] 92 90 [2] 85 9b [2] 9e d5 [2] a3 }

  condition:
    any of them
}