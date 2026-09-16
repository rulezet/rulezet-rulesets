rule TTP_XOR_MULT_DOSStub_b315 {
  strings:
    $key_b315 = { e7 7d [2] 93 65 [2] d4 67 [2] 93 76 [2] dd 7a [2] d1 70 [2] c6 7b [2] dd 35 [2] e0 }

  condition:
    any of them
}