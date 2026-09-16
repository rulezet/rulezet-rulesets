rule TTP_XOR_MULT_DOSStub_b545 {
  strings:
    $key_b545 = { e1 2d [2] 95 35 [2] d2 37 [2] 95 26 [2] db 2a [2] d7 20 [2] c0 2b [2] db 65 [2] e6 }

  condition:
    any of them
}