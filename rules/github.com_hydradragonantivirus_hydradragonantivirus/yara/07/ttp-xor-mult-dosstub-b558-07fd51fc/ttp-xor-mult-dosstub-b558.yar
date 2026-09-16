rule TTP_XOR_MULT_DOSStub_b558 {
  strings:
    $key_b558 = { e1 30 [2] 95 28 [2] d2 2a [2] 95 3b [2] db 37 [2] d7 3d [2] c0 36 [2] db 78 [2] e6 }

  condition:
    any of them
}