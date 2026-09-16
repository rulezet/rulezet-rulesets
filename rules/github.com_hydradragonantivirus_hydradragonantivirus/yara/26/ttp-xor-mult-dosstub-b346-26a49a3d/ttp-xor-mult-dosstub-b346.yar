rule TTP_XOR_MULT_DOSStub_b346 {
  strings:
    $key_b346 = { e7 2e [2] 93 36 [2] d4 34 [2] 93 25 [2] dd 29 [2] d1 23 [2] c6 28 [2] dd 66 [2] e0 }

  condition:
    any of them
}