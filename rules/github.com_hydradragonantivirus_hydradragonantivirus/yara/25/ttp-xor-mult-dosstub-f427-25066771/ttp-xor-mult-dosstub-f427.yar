rule TTP_XOR_MULT_DOSStub_f427 {
  strings:
    $key_f427 = { a0 4f [2] d4 57 [2] 93 55 [2] d4 44 [2] 9a 48 [2] 96 42 [2] 81 49 [2] 9a 07 [2] a7 }

  condition:
    any of them
}