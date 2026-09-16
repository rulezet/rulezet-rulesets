rule TTP_XOR_MULT_DOSStub_f406 {
  strings:
    $key_f406 = { a0 6e [2] d4 76 [2] 93 74 [2] d4 65 [2] 9a 69 [2] 96 63 [2] 81 68 [2] 9a 26 [2] a7 }

  condition:
    any of them
}