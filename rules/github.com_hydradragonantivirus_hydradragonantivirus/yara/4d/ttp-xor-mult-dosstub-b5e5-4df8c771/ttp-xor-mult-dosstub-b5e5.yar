rule TTP_XOR_MULT_DOSStub_b5e5 {
  strings:
    $key_b5e5 = { e1 8d [2] 95 95 [2] d2 97 [2] 95 86 [2] db 8a [2] d7 80 [2] c0 8b [2] db c5 [2] e6 }

  condition:
    any of them
}