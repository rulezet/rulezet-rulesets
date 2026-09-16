rule TTP_XOR_MULT_DOSStub_b651 {
  strings:
    $key_b651 = { e2 39 [2] 96 21 [2] d1 23 [2] 96 32 [2] d8 3e [2] d4 34 [2] c3 3f [2] d8 71 [2] e5 }

  condition:
    any of them
}