rule TTP_XOR_MULT_DOSStub_b3ec {
  strings:
    $key_b3ec = { e7 84 [2] 93 9c [2] d4 9e [2] 93 8f [2] dd 83 [2] d1 89 [2] c6 82 [2] dd cc [2] e0 }

  condition:
    any of them
}