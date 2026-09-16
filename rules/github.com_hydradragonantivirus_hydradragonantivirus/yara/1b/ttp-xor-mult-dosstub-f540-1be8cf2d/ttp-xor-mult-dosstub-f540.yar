rule TTP_XOR_MULT_DOSStub_f540 {
  strings:
    $key_f540 = { a1 28 [2] d5 30 [2] 92 32 [2] d5 23 [2] 9b 2f [2] 97 25 [2] 80 2e [2] 9b 60 [2] a6 }

  condition:
    any of them
}