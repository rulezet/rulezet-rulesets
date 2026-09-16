rule TTP_XOR_MULT_DOSStub_b364 {
  strings:
    $key_b364 = { e7 0c [2] 93 14 [2] d4 16 [2] 93 07 [2] dd 0b [2] d1 01 [2] c6 0a [2] dd 44 [2] e0 }

  condition:
    any of them
}