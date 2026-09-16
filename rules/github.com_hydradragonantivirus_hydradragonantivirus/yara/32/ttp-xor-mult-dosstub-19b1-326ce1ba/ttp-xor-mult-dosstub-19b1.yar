rule TTP_XOR_MULT_DOSStub_19b1 {
  strings:
    $key_19b1 = { 4d d9 [2] 39 c1 [2] 7e c3 [2] 39 d2 [2] 77 de [2] 7b d4 [2] 6c df [2] 77 91 [2] 4a }

  condition:
    any of them
}