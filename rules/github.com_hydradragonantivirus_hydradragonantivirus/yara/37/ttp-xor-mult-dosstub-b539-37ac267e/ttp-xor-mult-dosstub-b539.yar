rule TTP_XOR_MULT_DOSStub_b539 {
  strings:
    $key_b539 = { e1 51 [2] 95 49 [2] d2 4b [2] 95 5a [2] db 56 [2] d7 5c [2] c0 57 [2] db 19 [2] e6 }

  condition:
    any of them
}