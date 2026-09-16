rule TTP_XOR_MULT_DOSStub_f737 {
  strings:
    $key_f737 = { a3 5f [2] d7 47 [2] 90 45 [2] d7 54 [2] 99 58 [2] 95 52 [2] 82 59 [2] 99 17 [2] a4 }

  condition:
    any of them
}