rule TTP_XOR_MULT_DOSStub_b571 {
  strings:
    $key_b571 = { e1 19 [2] 95 01 [2] d2 03 [2] 95 12 [2] db 1e [2] d7 14 [2] c0 1f [2] db 51 [2] e6 }

  condition:
    any of them
}