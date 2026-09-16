rule TTP_XOR_MULT_DOSStub_b519 {
  strings:
    $key_b519 = { e1 71 [2] 95 69 [2] d2 6b [2] 95 7a [2] db 76 [2] d7 7c [2] c0 77 [2] db 39 [2] e6 }

  condition:
    any of them
}