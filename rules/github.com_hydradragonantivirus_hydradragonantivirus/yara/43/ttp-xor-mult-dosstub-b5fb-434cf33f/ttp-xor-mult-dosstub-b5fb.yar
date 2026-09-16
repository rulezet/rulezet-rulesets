rule TTP_XOR_MULT_DOSStub_b5fb {
  strings:
    $key_b5fb = { e1 93 [2] 95 8b [2] d2 89 [2] 95 98 [2] db 94 [2] d7 9e [2] c0 95 [2] db db [2] e6 }

  condition:
    any of them
}