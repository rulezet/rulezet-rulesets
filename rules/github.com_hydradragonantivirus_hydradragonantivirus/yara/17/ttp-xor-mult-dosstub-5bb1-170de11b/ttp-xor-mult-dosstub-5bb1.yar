rule TTP_XOR_MULT_DOSStub_5bb1 {
  strings:
    $key_5bb1 = { 0f d9 [2] 7b c1 [2] 3c c3 [2] 7b d2 [2] 35 de [2] 39 d4 [2] 2e df [2] 35 91 [2] 08 }

  condition:
    any of them
}