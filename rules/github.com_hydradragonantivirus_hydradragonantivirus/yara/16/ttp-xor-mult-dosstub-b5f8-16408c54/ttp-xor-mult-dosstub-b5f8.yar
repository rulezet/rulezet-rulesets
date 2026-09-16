rule TTP_XOR_MULT_DOSStub_b5f8 {
  strings:
    $key_b5f8 = { e1 90 [2] 95 88 [2] d2 8a [2] 95 9b [2] db 97 [2] d7 9d [2] c0 96 [2] db d8 [2] e6 }

  condition:
    any of them
}