rule TTP_XOR_MULT_DOSStub_f046 {
  strings:
    $key_f046 = { a4 2e [2] d0 36 [2] 97 34 [2] d0 25 [2] 9e 29 [2] 92 23 [2] 85 28 [2] 9e 66 [2] a3 }

  condition:
    any of them
}