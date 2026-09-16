rule TTP_XOR_MULT_DOSStub_b3e5 {
  strings:
    $key_b3e5 = { e7 8d [2] 93 95 [2] d4 97 [2] 93 86 [2] dd 8a [2] d1 80 [2] c6 8b [2] dd c5 [2] e0 }

  condition:
    any of them
}