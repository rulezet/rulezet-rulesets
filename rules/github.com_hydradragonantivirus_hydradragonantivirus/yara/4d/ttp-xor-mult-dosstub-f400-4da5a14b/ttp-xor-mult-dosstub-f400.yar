rule TTP_XOR_MULT_DOSStub_f400 {
  strings:
    $key_f400 = { a0 68 [2] d4 70 [2] 93 72 [2] d4 63 [2] 9a 6f [2] 96 65 [2] 81 6e [2] 9a 20 [2] a7 }

  condition:
    any of them
}