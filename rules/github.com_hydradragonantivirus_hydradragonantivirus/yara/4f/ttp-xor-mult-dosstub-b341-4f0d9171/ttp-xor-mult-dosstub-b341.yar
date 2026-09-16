rule TTP_XOR_MULT_DOSStub_b341 {
  strings:
    $key_b341 = { e7 29 [2] 93 31 [2] d4 33 [2] 93 22 [2] dd 2e [2] d1 24 [2] c6 2f [2] dd 61 [2] e0 }

  condition:
    any of them
}