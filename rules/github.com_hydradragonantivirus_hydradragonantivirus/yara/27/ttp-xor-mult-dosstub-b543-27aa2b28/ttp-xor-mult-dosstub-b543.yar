rule TTP_XOR_MULT_DOSStub_b543 {
  strings:
    $key_b543 = { e1 2b [2] 95 33 [2] d2 31 [2] 95 20 [2] db 2c [2] d7 26 [2] c0 2d [2] db 63 [2] e6 }

  condition:
    any of them
}