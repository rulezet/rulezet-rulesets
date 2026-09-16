rule TTP_XOR_MULT_DOSStub_b512 {
  strings:
    $key_b512 = { e1 7a [2] 95 62 [2] d2 60 [2] 95 71 [2] db 7d [2] d7 77 [2] c0 7c [2] db 32 [2] e6 }

  condition:
    any of them
}