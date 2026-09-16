rule TTP_XOR_MULT_DOSStub_b515 {
  strings:
    $key_b515 = { e1 7d [2] 95 65 [2] d2 67 [2] 95 76 [2] db 7a [2] d7 70 [2] c0 7b [2] db 35 [2] e6 }

  condition:
    any of them
}