rule TTP_XOR_MULT_DOSStub_b379 {
  strings:
    $key_b379 = { e7 11 [2] 93 09 [2] d4 0b [2] 93 1a [2] dd 16 [2] d1 1c [2] c6 17 [2] dd 59 [2] e0 }

  condition:
    any of them
}