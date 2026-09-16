rule TTP_XOR_MULT_DOSStub_daa2 {
  strings:
    $key_daa2 = { 8e ca [2] fa d2 [2] bd d0 [2] fa c1 [2] b4 cd [2] b8 c7 [2] af cc [2] b4 82 [2] 89 }

  condition:
    any of them
}