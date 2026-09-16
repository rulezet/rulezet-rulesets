rule TTP_XOR_MULT_DOSStub_b5e7 {
  strings:
    $key_b5e7 = { e1 8f [2] 95 97 [2] d2 95 [2] 95 84 [2] db 88 [2] d7 82 [2] c0 89 [2] db c7 [2] e6 }

  condition:
    any of them
}