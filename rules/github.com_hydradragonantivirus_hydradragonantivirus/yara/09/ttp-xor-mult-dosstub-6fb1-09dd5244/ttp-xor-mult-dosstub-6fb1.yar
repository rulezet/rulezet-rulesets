rule TTP_XOR_MULT_DOSStub_6fb1 {
  strings:
    $key_6fb1 = { 3b d9 [2] 4f c1 [2] 08 c3 [2] 4f d2 [2] 01 de [2] 0d d4 [2] 1a df [2] 01 91 [2] 3c }

  condition:
    any of them
}