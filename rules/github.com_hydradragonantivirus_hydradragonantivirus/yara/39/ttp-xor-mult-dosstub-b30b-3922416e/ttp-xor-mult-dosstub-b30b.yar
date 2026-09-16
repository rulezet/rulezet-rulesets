rule TTP_XOR_MULT_DOSStub_b30b {
  strings:
    $key_b30b = { e7 63 [2] 93 7b [2] d4 79 [2] 93 68 [2] dd 64 [2] d1 6e [2] c6 65 [2] dd 2b [2] e0 }

  condition:
    any of them
}