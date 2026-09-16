rule TTP_XOR_MULT_DOSStub_b540 {
  strings:
    $key_b540 = { e1 28 [2] 95 30 [2] d2 32 [2] 95 23 [2] db 2f [2] d7 25 [2] c0 2e [2] db 60 [2] e6 }

  condition:
    any of them
}