rule TTP_XOR_MULT_DOSStub_f146 {
  strings:
    $key_f146 = { a5 2e [2] d1 36 [2] 96 34 [2] d1 25 [2] 9f 29 [2] 93 23 [2] 84 28 [2] 9f 66 [2] a2 }

  condition:
    any of them
}