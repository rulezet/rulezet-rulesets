rule TTP_XOR_MULT_DOSStub_b57d {
  strings:
    $key_b57d = { e1 15 [2] 95 0d [2] d2 0f [2] 95 1e [2] db 12 [2] d7 18 [2] c0 13 [2] db 5d [2] e6 }

  condition:
    any of them
}