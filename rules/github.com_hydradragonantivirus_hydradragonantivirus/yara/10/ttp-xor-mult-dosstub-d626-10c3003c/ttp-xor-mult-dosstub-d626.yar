rule TTP_XOR_MULT_DOSStub_d626 {
  strings:
    $key_d626 = { 82 4e [2] f6 56 [2] b1 54 [2] f6 45 [2] b8 49 [2] b4 43 [2] a3 48 [2] b8 06 [2] 85 }

  condition:
    any of them
}