rule TTP_XOR_MULT_DOSStub_b3f5 {
  strings:
    $key_b3f5 = { e7 9d [2] 93 85 [2] d4 87 [2] 93 96 [2] dd 9a [2] d1 90 [2] c6 9b [2] dd d5 [2] e0 }

  condition:
    any of them
}