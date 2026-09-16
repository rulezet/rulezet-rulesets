rule TTP_XOR_MULT_DOSStub_b574 {
  strings:
    $key_b574 = { e1 1c [2] 95 04 [2] d2 06 [2] 95 17 [2] db 1b [2] d7 11 [2] c0 1a [2] db 54 [2] e6 }

  condition:
    any of them
}