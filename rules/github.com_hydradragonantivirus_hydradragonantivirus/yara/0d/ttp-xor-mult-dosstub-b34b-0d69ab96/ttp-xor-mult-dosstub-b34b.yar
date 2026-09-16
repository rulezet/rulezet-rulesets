rule TTP_XOR_MULT_DOSStub_b34b {
  strings:
    $key_b34b = { e7 23 [2] 93 3b [2] d4 39 [2] 93 28 [2] dd 24 [2] d1 2e [2] c6 25 [2] dd 6b [2] e0 }

  condition:
    any of them
}