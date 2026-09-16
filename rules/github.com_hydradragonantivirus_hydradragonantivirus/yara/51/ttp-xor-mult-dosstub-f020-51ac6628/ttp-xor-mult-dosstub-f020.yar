rule TTP_XOR_MULT_DOSStub_f020 {
  strings:
    $key_f020 = { a4 48 [2] d0 50 [2] 97 52 [2] d0 43 [2] 9e 4f [2] 92 45 [2] 85 4e [2] 9e 00 [2] a3 }

  condition:
    any of them
}