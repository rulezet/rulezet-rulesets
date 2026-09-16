rule TTP_XOR_MULT_DOSStub_b354 {
  strings:
    $key_b354 = { e7 3c [2] 93 24 [2] d4 26 [2] 93 37 [2] dd 3b [2] d1 31 [2] c6 3a [2] dd 74 [2] e0 }

  condition:
    any of them
}