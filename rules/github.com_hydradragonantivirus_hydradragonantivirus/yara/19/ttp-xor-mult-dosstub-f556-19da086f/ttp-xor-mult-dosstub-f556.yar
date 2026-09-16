rule TTP_XOR_MULT_DOSStub_f556 {
  strings:
    $key_f556 = { a1 3e [2] d5 26 [2] 92 24 [2] d5 35 [2] 9b 39 [2] 97 33 [2] 80 38 [2] 9b 76 [2] a6 }

  condition:
    any of them
}