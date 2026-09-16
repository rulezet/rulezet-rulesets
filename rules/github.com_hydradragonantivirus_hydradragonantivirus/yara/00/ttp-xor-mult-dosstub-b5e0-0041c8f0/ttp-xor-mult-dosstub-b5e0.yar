rule TTP_XOR_MULT_DOSStub_b5e0 {
  strings:
    $key_b5e0 = { e1 88 [2] 95 90 [2] d2 92 [2] 95 83 [2] db 8f [2] d7 85 [2] c0 8e [2] db c0 [2] e6 }

  condition:
    any of them
}