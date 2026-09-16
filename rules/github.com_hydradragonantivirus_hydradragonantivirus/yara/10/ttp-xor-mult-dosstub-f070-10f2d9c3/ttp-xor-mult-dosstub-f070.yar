rule TTP_XOR_MULT_DOSStub_f070 {
  strings:
    $key_f070 = { a4 18 [2] d0 00 [2] 97 02 [2] d0 13 [2] 9e 1f [2] 92 15 [2] 85 1e [2] 9e 50 [2] a3 }

  condition:
    any of them
}