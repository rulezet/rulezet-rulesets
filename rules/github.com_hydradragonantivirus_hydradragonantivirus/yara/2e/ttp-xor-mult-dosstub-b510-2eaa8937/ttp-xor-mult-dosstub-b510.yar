rule TTP_XOR_MULT_DOSStub_b510 {
  strings:
    $key_b510 = { e1 78 [2] 95 60 [2] d2 62 [2] 95 73 [2] db 7f [2] d7 75 [2] c0 7e [2] db 30 [2] e6 }

  condition:
    any of them
}