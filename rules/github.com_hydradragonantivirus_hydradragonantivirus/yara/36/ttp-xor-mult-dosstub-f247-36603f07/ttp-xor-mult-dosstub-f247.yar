rule TTP_XOR_MULT_DOSStub_f247 {
  strings:
    $key_f247 = { a6 2f [2] d2 37 [2] 95 35 [2] d2 24 [2] 9c 28 [2] 90 22 [2] 87 29 [2] 9c 67 [2] a1 }

  condition:
    any of them
}