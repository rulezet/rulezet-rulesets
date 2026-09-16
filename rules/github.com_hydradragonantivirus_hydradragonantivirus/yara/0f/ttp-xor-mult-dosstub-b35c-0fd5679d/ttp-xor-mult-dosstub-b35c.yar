rule TTP_XOR_MULT_DOSStub_b35c {
  strings:
    $key_b35c = { e7 34 [2] 93 2c [2] d4 2e [2] 93 3f [2] dd 33 [2] d1 39 [2] c6 32 [2] dd 7c [2] e0 }

  condition:
    any of them
}