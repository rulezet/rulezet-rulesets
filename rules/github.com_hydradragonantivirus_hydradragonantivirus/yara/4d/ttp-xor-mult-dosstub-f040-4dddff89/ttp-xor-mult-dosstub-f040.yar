rule TTP_XOR_MULT_DOSStub_f040 {
  strings:
    $key_f040 = { a4 28 [2] d0 30 [2] 97 32 [2] d0 23 [2] 9e 2f [2] 92 25 [2] 85 2e [2] 9e 60 [2] a3 }

  condition:
    any of them
}