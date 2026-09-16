rule TTP_XOR_MULT_DOSStub_b570 {
  strings:
    $key_b570 = { e1 18 [2] 95 00 [2] d2 02 [2] 95 13 [2] db 1f [2] d7 15 [2] c0 1e [2] db 50 [2] e6 }

  condition:
    any of them
}