rule TTP_XOR_MULT_DOSStub_f461 {
  strings:
    $key_f461 = { a0 09 [2] d4 11 [2] 93 13 [2] d4 02 [2] 9a 0e [2] 96 04 [2] 81 0f [2] 9a 41 [2] a7 }

  condition:
    any of them
}