rule TTP_XOR_MULT_DOSStub_f0f1 {
  strings:
    $key_f0f1 = { a4 99 [2] d0 81 [2] 97 83 [2] d0 92 [2] 9e 9e [2] 92 94 [2] 85 9f [2] 9e d1 [2] a3 }

  condition:
    any of them
}