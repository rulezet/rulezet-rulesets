rule TTP_XOR_MULT_DOSStub_f2f6 {
  strings:
    $key_f2f6 = { a6 9e [2] d2 86 [2] 95 84 [2] d2 95 [2] 9c 99 [2] 90 93 [2] 87 98 [2] 9c d6 [2] a1 }

  condition:
    any of them
}