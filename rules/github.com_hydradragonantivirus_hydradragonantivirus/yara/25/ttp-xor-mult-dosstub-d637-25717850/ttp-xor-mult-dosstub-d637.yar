rule TTP_XOR_MULT_DOSStub_d637 {
  strings:
    $key_d637 = { 82 5f [2] f6 47 [2] b1 45 [2] f6 54 [2] b8 58 [2] b4 52 [2] a3 59 [2] b8 17 [2] 85 }

  condition:
    any of them
}