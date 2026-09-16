rule TTP_XOR_MULT_DOSStub_b537 {
  strings:
    $key_b537 = { e1 5f [2] 95 47 [2] d2 45 [2] 95 54 [2] db 58 [2] d7 52 [2] c0 59 [2] db 17 [2] e6 }

  condition:
    any of them
}