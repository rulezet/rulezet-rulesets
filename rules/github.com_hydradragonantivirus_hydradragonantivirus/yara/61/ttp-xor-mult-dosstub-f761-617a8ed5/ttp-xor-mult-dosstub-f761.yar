rule TTP_XOR_MULT_DOSStub_f761 {
  strings:
    $key_f761 = { a3 09 [2] d7 11 [2] 90 13 [2] d7 02 [2] 99 0e [2] 95 04 [2] 82 0f [2] 99 41 [2] a4 }

  condition:
    any of them
}