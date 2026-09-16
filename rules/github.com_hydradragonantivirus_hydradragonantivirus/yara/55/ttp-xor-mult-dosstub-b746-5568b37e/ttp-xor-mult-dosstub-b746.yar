rule TTP_XOR_MULT_DOSStub_b746 {
  strings:
    $key_b746 = { e3 2e [2] 97 36 [2] d0 34 [2] 97 25 [2] d9 29 [2] d5 23 [2] c2 28 [2] d9 66 [2] e4 }

  condition:
    any of them
}