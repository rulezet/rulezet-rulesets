rule TTP_XOR_MULT_DOSStub_b5e6 {
  strings:
    $key_b5e6 = { e1 8e [2] 95 96 [2] d2 94 [2] 95 85 [2] db 89 [2] d7 83 [2] c0 88 [2] db c6 [2] e6 }

  condition:
    any of them
}