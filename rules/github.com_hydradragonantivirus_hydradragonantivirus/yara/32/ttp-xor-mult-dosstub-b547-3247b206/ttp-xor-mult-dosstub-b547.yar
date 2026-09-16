rule TTP_XOR_MULT_DOSStub_b547 {
  strings:
    $key_b547 = { e1 2f [2] 95 37 [2] d2 35 [2] 95 24 [2] db 28 [2] d7 22 [2] c0 29 [2] db 67 [2] e6 }

  condition:
    any of them
}