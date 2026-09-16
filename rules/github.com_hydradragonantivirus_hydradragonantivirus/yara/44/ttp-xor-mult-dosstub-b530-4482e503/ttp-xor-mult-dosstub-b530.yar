rule TTP_XOR_MULT_DOSStub_b530 {
  strings:
    $key_b530 = { e1 58 [2] 95 40 [2] d2 42 [2] 95 53 [2] db 5f [2] d7 55 [2] c0 5e [2] db 10 [2] e6 }

  condition:
    any of them
}