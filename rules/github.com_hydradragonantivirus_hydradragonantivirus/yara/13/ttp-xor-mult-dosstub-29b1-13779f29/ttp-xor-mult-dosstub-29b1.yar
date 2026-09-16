rule TTP_XOR_MULT_DOSStub_29b1 {
  strings:
    $key_29b1 = { 7d d9 [2] 09 c1 [2] 4e c3 [2] 09 d2 [2] 47 de [2] 4b d4 [2] 5c df [2] 47 91 [2] 7a }

  condition:
    any of them
}