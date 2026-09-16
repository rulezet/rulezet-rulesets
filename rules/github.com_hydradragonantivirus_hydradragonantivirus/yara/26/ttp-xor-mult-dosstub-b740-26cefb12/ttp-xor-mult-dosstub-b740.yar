rule TTP_XOR_MULT_DOSStub_b740 {
  strings:
    $key_b740 = { e3 28 [2] 97 30 [2] d0 32 [2] 97 23 [2] d9 2f [2] d5 25 [2] c2 2e [2] d9 60 [2] e4 }

  condition:
    any of them
}