rule TTP_XOR_MULT_DOSStub_f740 {
  strings:
    $key_f740 = { a3 28 [2] d7 30 [2] 90 32 [2] d7 23 [2] 99 2f [2] 95 25 [2] 82 2e [2] 99 60 [2] a4 }

  condition:
    any of them
}