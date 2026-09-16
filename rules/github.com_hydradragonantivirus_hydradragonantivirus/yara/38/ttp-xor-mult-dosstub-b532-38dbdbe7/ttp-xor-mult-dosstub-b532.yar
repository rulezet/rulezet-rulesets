rule TTP_XOR_MULT_DOSStub_b532 {
  strings:
    $key_b532 = { e1 5a [2] 95 42 [2] d2 40 [2] 95 51 [2] db 5d [2] d7 57 [2] c0 5c [2] db 12 [2] e6 }

  condition:
    any of them
}