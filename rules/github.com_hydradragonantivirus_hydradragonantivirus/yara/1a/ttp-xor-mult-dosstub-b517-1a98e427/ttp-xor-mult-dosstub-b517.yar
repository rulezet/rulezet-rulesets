rule TTP_XOR_MULT_DOSStub_b517 {
  strings:
    $key_b517 = { e1 7f [2] 95 67 [2] d2 65 [2] 95 74 [2] db 78 [2] d7 72 [2] c0 79 [2] db 37 [2] e6 }

  condition:
    any of them
}