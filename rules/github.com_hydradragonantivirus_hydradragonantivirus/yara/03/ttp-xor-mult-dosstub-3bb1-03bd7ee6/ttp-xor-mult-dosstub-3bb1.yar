rule TTP_XOR_MULT_DOSStub_3bb1 {
  strings:
    $key_3bb1 = { 6f d9 [2] 1b c1 [2] 5c c3 [2] 1b d2 [2] 55 de [2] 59 d4 [2] 4e df [2] 55 91 [2] 68 }

  condition:
    any of them
}