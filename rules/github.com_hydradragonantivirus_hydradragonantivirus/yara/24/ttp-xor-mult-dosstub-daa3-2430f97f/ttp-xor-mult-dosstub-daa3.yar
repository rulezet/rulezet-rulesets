rule TTP_XOR_MULT_DOSStub_daa3 {
  strings:
    $key_daa3 = { 8e cb [2] fa d3 [2] bd d1 [2] fa c0 [2] b4 cc [2] b8 c6 [2] af cd [2] b4 83 [2] 89 }

  condition:
    any of them
}