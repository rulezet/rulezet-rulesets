rule TTP_XOR_MULT_DOSStub_b565 {
  strings:
    $key_b565 = { e1 0d [2] 95 15 [2] d2 17 [2] 95 06 [2] db 0a [2] d7 00 [2] c0 0b [2] db 45 [2] e6 }

  condition:
    any of them
}