rule TTP_XOR_MULT_DOSStub_f730 {
  strings:
    $key_f730 = { a3 58 [2] d7 40 [2] 90 42 [2] d7 53 [2] 99 5f [2] 95 55 [2] 82 5e [2] 99 10 [2] a4 }

  condition:
    any of them
}