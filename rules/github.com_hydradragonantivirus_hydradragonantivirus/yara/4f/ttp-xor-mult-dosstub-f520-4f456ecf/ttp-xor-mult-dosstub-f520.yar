rule TTP_XOR_MULT_DOSStub_f520 {
  strings:
    $key_f520 = { a1 48 [2] d5 50 [2] 92 52 [2] d5 43 [2] 9b 4f [2] 97 45 [2] 80 4e [2] 9b 00 [2] a6 }

  condition:
    any of them
}