rule TTP_XOR_MULT_DOSStub_f031 {
  strings:
    $key_f031 = { a4 59 [2] d0 41 [2] 97 43 [2] d0 52 [2] 9e 5e [2] 92 54 [2] 85 5f [2] 9e 11 [2] a3 }

  condition:
    any of them
}