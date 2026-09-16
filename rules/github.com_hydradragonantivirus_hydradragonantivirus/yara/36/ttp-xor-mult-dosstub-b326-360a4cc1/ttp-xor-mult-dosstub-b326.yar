rule TTP_XOR_MULT_DOSStub_b326 {
  strings:
    $key_b326 = { e7 4e [2] 93 56 [2] d4 54 [2] 93 45 [2] dd 49 [2] d1 43 [2] c6 48 [2] dd 06 [2] e0 }

  condition:
    any of them
}