rule TTP_XOR_MULT_DOSStub_b534 {
  strings:
    $key_b534 = { e1 5c [2] 95 44 [2] d2 46 [2] 95 57 [2] db 5b [2] d7 51 [2] c0 5a [2] db 14 [2] e6 }

  condition:
    any of them
}