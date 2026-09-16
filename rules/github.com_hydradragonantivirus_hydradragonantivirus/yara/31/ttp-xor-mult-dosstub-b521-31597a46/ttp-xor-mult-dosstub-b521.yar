rule TTP_XOR_MULT_DOSStub_b521 {
  strings:
    $key_b521 = { e1 49 [2] 95 51 [2] d2 53 [2] 95 42 [2] db 4e [2] d7 44 [2] c0 4f [2] db 01 [2] e6 }

  condition:
    any of them
}