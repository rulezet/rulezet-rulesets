rule TTP_XOR_MULT_DOSStub_f426 {
  strings:
    $key_f426 = { a0 4e [2] d4 56 [2] 93 54 [2] d4 45 [2] 9a 49 [2] 96 43 [2] 81 48 [2] 9a 06 [2] a7 }

  condition:
    any of them
}