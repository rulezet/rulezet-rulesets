rule TTP_XOR_MULT_DOSStub_f446 {
  strings:
    $key_f446 = { a0 2e [2] d4 36 [2] 93 34 [2] d4 25 [2] 9a 29 [2] 96 23 [2] 81 28 [2] 9a 66 [2] a7 }

  condition:
    any of them
}