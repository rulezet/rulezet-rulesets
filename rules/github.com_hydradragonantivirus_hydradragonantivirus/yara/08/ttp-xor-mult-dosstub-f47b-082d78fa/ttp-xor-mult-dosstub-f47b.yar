rule TTP_XOR_MULT_DOSStub_f47b {
  strings:
    $key_f47b = { a0 13 [2] d4 0b [2] 93 09 [2] d4 18 [2] 9a 14 [2] 96 1e [2] 81 15 [2] 9a 5b [2] a7 }

  condition:
    any of them
}