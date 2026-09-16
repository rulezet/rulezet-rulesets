rule TTP_XOR_MULT_DOSStub_f767 {
  strings:
    $key_f767 = { a3 0f [2] d7 17 [2] 90 15 [2] d7 04 [2] 99 08 [2] 95 02 [2] 82 09 [2] 99 47 [2] a4 }

  condition:
    any of them
}