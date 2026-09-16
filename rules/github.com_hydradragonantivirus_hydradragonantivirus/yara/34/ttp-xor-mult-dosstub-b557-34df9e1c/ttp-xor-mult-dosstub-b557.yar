rule TTP_XOR_MULT_DOSStub_b557 {
  strings:
    $key_b557 = { e1 3f [2] 95 27 [2] d2 25 [2] 95 34 [2] db 38 [2] d7 32 [2] c0 39 [2] db 77 [2] e6 }

  condition:
    any of them
}