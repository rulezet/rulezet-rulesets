rule TTP_XOR_MULT_DOSStub_f240 {
  strings:
    $key_f240 = { a6 28 [2] d2 30 [2] 95 32 [2] d2 23 [2] 9c 2f [2] 90 25 [2] 87 2e [2] 9c 60 [2] a1 }

  condition:
    any of them
}