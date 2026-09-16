rule TTP_XOR_MULT_DOSStub_daa4 {
  strings:
    $key_daa4 = { 8e cc [2] fa d4 [2] bd d6 [2] fa c7 [2] b4 cb [2] b8 c1 [2] af ca [2] b4 84 [2] 89 }

  condition:
    any of them
}