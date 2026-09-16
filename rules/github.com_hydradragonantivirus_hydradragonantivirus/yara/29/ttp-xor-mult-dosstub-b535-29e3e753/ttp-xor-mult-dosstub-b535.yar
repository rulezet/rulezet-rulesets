rule TTP_XOR_MULT_DOSStub_b535 {
  strings:
    $key_b535 = { e1 5d [2] 95 45 [2] d2 47 [2] 95 56 [2] db 5a [2] d7 50 [2] c0 5b [2] db 15 [2] e6 }

  condition:
    any of them
}