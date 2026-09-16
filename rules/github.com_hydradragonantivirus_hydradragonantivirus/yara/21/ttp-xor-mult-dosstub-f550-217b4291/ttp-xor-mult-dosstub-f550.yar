rule TTP_XOR_MULT_DOSStub_f550 {
  strings:
    $key_f550 = { a1 38 [2] d5 20 [2] 92 22 [2] d5 33 [2] 9b 3f [2] 97 35 [2] 80 3e [2] 9b 70 [2] a6 }

  condition:
    any of them
}