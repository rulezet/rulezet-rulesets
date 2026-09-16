rule TTP_XOR_MULT_DOSStub_b577 {
  strings:
    $key_b577 = { e1 1f [2] 95 07 [2] d2 05 [2] 95 14 [2] db 18 [2] d7 12 [2] c0 19 [2] db 57 [2] e6 }

  condition:
    any of them
}