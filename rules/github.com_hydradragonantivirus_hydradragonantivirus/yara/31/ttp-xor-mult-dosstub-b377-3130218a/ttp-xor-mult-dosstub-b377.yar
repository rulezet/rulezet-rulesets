rule TTP_XOR_MULT_DOSStub_b377 {
  strings:
    $key_b377 = { e7 1f [2] 93 07 [2] d4 05 [2] 93 14 [2] dd 18 [2] d1 12 [2] c6 19 [2] dd 57 [2] e0 }

  condition:
    any of them
}