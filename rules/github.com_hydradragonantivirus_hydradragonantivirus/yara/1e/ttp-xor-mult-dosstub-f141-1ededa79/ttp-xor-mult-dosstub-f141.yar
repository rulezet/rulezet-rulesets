rule TTP_XOR_MULT_DOSStub_f141 {
  strings:
    $key_f141 = { a5 29 [2] d1 31 [2] 96 33 [2] d1 22 [2] 9f 2e [2] 93 24 [2] 84 2f [2] 9f 61 [2] a2 }

  condition:
    any of them
}