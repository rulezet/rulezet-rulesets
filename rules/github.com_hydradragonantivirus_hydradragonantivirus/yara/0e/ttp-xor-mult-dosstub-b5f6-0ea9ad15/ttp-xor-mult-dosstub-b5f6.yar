rule TTP_XOR_MULT_DOSStub_b5f6 {
  strings:
    $key_b5f6 = { e1 9e [2] 95 86 [2] d2 84 [2] 95 95 [2] db 99 [2] d7 93 [2] c0 98 [2] db d6 [2] e6 }

  condition:
    any of them
}