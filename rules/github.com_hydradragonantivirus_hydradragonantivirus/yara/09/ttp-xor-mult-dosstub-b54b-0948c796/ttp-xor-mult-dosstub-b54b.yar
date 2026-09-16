rule TTP_XOR_MULT_DOSStub_b54b {
  strings:
    $key_b54b = { e1 23 [2] 95 3b [2] d2 39 [2] 95 28 [2] db 24 [2] d7 2e [2] c0 25 [2] db 6b [2] e6 }

  condition:
    any of them
}