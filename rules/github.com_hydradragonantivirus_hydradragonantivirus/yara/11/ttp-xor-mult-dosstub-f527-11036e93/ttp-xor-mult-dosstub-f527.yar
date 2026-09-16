rule TTP_XOR_MULT_DOSStub_f527 {
  strings:
    $key_f527 = { a1 4f [2] d5 57 [2] 92 55 [2] d5 44 [2] 9b 48 [2] 97 42 [2] 80 49 [2] 9b 07 [2] a6 }

  condition:
    any of them
}