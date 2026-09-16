rule TTP_XOR_MULT_DOSStub_f460 {
  strings:
    $key_f460 = { a0 08 [2] d4 10 [2] 93 12 [2] d4 03 [2] 9a 0f [2] 96 05 [2] 81 0e [2] 9a 40 [2] a7 }

  condition:
    any of them
}