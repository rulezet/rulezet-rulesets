rule TTP_XOR_MULT_DOSStub_f551 {
  strings:
    $key_f551 = { a1 39 [2] d5 21 [2] 92 23 [2] d5 32 [2] 9b 3e [2] 97 34 [2] 80 3f [2] 9b 71 [2] a6 }

  condition:
    any of them
}