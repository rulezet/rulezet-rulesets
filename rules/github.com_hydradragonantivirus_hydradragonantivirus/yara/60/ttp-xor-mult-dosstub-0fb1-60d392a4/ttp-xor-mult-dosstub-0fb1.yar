rule TTP_XOR_MULT_DOSStub_0fb1 {
  strings:
    $key_0fb1 = { 5b d9 [2] 2f c1 [2] 68 c3 [2] 2f d2 [2] 61 de [2] 6d d4 [2] 7a df [2] 61 91 [2] 5c }

  condition:
    any of them
}