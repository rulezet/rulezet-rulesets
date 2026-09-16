rule TTP_XOR_MULT_DOSStub_d631 {
  strings:
    $key_d631 = { 82 59 [2] f6 41 [2] b1 43 [2] f6 52 [2] b8 5e [2] b4 54 [2] a3 5f [2] b8 11 [2] 85 }

  condition:
    any of them
}