rule TTP_XOR_MULT_DOSStub_6bb1 {
  strings:
    $key_6bb1 = { 3f d9 [2] 4b c1 [2] 0c c3 [2] 4b d2 [2] 05 de [2] 09 d4 [2] 1e df [2] 05 91 [2] 38 }

  condition:
    any of them
}