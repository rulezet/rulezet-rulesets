rule TTP_XOR_MULT_DOSStub_b556 {
  strings:
    $key_b556 = { e1 3e [2] 95 26 [2] d2 24 [2] 95 35 [2] db 39 [2] d7 33 [2] c0 38 [2] db 76 [2] e6 }

  condition:
    any of them
}