rule TTP_XOR_MULT_DOSStub_f431 {
  strings:
    $key_f431 = { a0 59 [2] d4 41 [2] 93 43 [2] d4 52 [2] 9a 5e [2] 96 54 [2] 81 5f [2] 9a 11 [2] a7 }

  condition:
    any of them
}