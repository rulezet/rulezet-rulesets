rule TTP_XOR_MULT_DOSStub_f441 {
  strings:
    $key_f441 = { a0 29 [2] d4 31 [2] 93 33 [2] d4 22 [2] 9a 2e [2] 96 24 [2] 81 2f [2] 9a 61 [2] a7 }

  condition:
    any of them
}