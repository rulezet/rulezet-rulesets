rule TTP_XOR_MULT_DOSStub_b559 {
  strings:
    $key_b559 = { e1 31 [2] 95 29 [2] d2 2b [2] 95 3a [2] db 36 [2] d7 3c [2] c0 37 [2] db 79 [2] e6 }

  condition:
    any of them
}