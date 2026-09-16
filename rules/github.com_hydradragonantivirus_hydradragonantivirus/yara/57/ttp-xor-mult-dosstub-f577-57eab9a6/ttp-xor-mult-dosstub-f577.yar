rule TTP_XOR_MULT_DOSStub_f577 {
  strings:
    $key_f577 = { a1 1f [2] d5 07 [2] 92 05 [2] d5 14 [2] 9b 18 [2] 97 12 [2] 80 19 [2] 9b 57 [2] a6 }

  condition:
    any of them
}