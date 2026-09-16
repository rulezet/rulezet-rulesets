rule TTP_XOR_MULT_DOSStub_b5e4 {
  strings:
    $key_b5e4 = { e1 8c [2] 95 94 [2] d2 96 [2] 95 87 [2] db 8b [2] d7 81 [2] c0 8a [2] db c4 [2] e6 }

  condition:
    any of them
}