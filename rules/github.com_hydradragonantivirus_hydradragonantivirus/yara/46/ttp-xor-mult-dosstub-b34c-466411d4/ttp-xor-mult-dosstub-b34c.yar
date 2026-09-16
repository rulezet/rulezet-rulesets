rule TTP_XOR_MULT_DOSStub_b34c {
  strings:
    $key_b34c = { e7 24 [2] 93 3c [2] d4 3e [2] 93 2f [2] dd 23 [2] d1 29 [2] c6 22 [2] dd 6c [2] e0 }

  condition:
    any of them
}