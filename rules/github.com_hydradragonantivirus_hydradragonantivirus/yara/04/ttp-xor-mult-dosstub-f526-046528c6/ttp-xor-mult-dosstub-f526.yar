rule TTP_XOR_MULT_DOSStub_f526 {
  strings:
    $key_f526 = { a1 4e [2] d5 56 [2] 92 54 [2] d5 45 [2] 9b 49 [2] 97 43 [2] 80 48 [2] 9b 06 [2] a6 }

  condition:
    any of them
}