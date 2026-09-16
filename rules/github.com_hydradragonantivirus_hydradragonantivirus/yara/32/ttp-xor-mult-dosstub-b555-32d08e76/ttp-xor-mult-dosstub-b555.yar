rule TTP_XOR_MULT_DOSStub_b555 {
  strings:
    $key_b555 = { e1 3d [2] 95 25 [2] d2 27 [2] 95 36 [2] db 3a [2] d7 30 [2] c0 3b [2] db 75 [2] e6 }

  condition:
    any of them
}